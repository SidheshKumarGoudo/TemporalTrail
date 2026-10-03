use std::env;
use std::path::PathBuf;
use tt_engine::{Engine, NodeRef, Result, MAIN};

fn tt_home() -> PathBuf {
    env::var("TT_HOME").unwrap_or_else(|_| ".tt".to_string()).into()
}

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    if let Err(e) = run(&args) {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

fn run(args: &[String]) -> Result<()> {
    let cmd = args.get(0).map(|s| s.as_str()).unwrap_or("status");
    let home = tt_home();
    let e = Engine::open(&home)?;

    match cmd {
        "init" => {
            println!("initialized TemporalTrail repo at {}", home.display());
            println!("MAIN -> n{}", e.get_timeline(MAIN)?.head_node_id);
        }

        "status" => {
            let cur = e.current_timeline_name()?;
            let cur_tl = e.get_timeline(&cur)?;
            let main = e.get_timeline(MAIN)?;
            println!("current timeline: {cur} (HEAD n{})", cur_tl.head_node_id);
            println!("MAIN HEAD: n{}", main.head_node_id);
            let node = e.get_node(cur_tl.head_node_id)?;
            println!("state: {:?}", node.fake_state);
        }

        "timelines" => {
            for t in e.list_timelines()? {
                println!(
                    "{}{} -> n{}",
                    if t.is_main { "* " } else { "  " },
                    t.name,
                    t.head_node_id
                );
            }
        }

        "enter" => {
            let name = args.get(1).cloned().unwrap_or(e.current_timeline_name()?);
            let merged = e.mount(&name)?;
            e.switch(&name)?;
            println!("{name} mounted at: {}", merged.display());
            println!("cd there and edit real files, then run: tl checkpoint -m \"message\"");
        }

        "leave" => {
            let name = args.get(1).cloned().unwrap_or(e.current_timeline_name()?);
            e.unmount(&name)?;
            println!("{name} unmounted");
        }

        "checkpoint" => {
            let msg = flag_value(args, "-m");
            let cur = e.current_timeline_name()?;
            let node = e.checkpoint_from_live(&cur, msg.as_deref())?;
            println!("n{} committed on {cur}", node.id);
            println!("contents: {}", node.fake_state);
        }

        "fork" => {
            let new_name = args.get(1).ok_or_else(|| tt_engine::EngineError(
                "usage: tl fork <new-timeline-name> --from <ref>".into(),
            ))?;
            let from = flag_value(args, "--from").unwrap_or_else(|| {
                // default: fork from current timeline's HEAD
                e.current_timeline_name().unwrap_or_else(|_| MAIN.to_string())
            });
            let source = NodeRef::parse(&from);
            let tl = e.fork(&source, new_name)?;
            println!("forked '{}' -> n{} (no new Node created)", tl.name, tl.head_node_id);
            e.switch(new_name)?;
            println!("switched to {new_name}");
        }

        "switch" => {
            let name = args.get(1).ok_or_else(|| tt_engine::EngineError(
                "usage: tl switch <timeline-name>".into(),
            ))?;
            e.switch(name)?;
            println!("switched to {name}");
        }

        "log" => {
            let tl_name = args.get(1).cloned().unwrap_or(e.current_timeline_name()?);
            for n in e.log(&tl_name)? {
                println!(
                    "n{}  parent={}  {}  {:?}",
                    n.id,
                    n.parent_id.map(|p| format!("n{p}")).unwrap_or_else(|| "-".into()),
                    n.action_desc.unwrap_or_default(),
                    n.fake_state
                );
            }
        }

        "diff" => {
            let a = parse_node_id(args.get(1))?;
            let b = parse_node_id(args.get(2))?;
            let (na, nb, same) = e.diff(a, b)?;
            println!("n{}: {:?}", na.id, na.fake_state);
            println!("n{}: {:?}", nb.id, nb.fake_state);
            println!("{}", if same { "identical" } else { "differs" });
        }

        "validate" => {
            let node_ref = args.get(1).ok_or_else(|| tt_engine::EngineError(
                "usage: tl validate <node-ref> <PASS|FAIL> [--validator name]".into(),
            ))?;
            let status = args.get(2).ok_or_else(|| tt_engine::EngineError(
                "usage: tl validate <node-ref> <PASS|FAIL> [--validator name]".into(),
            ))?;
            let node_id = e.resolve(&NodeRef::parse(node_ref))?;
            let validator = flag_value(args, "--validator");
            let v = e.validate(node_id, status, validator.as_deref())?;
            println!("validation #{} recorded: n{} -> {}", v.id, v.node_id, v.status);
        }

        "allow" | "deny" => {
            let target = args.get(1).ok_or_else(|| tt_engine::EngineError(
                "usage: tl allow|deny <target-host>".into(),
            ))?;
            let cur = e.current_timeline_name()?;
            let head = e.get_timeline(&cur)?.head_node_id;
            let decision = if cmd == "allow" { "ALLOW" } else { "DENY" };
            e.log_external_interaction(&cur, head, target, decision)?;
            println!("{decision} {target} logged on {cur} @ n{head}");
        }
        
        "gateway" => {
            let usage = || tt_engine::EngineError(
                "usage: tl gateway up <timeline> [ip|cidr ...] | down <timeline> | exec <timeline> -- <cmd...>".into(),
            );
            let ge = |e: tt_engine::gateway::GatewayError| tt_engine::EngineError(e.to_string());
            let sub = args.get(1).map(|s| s.as_str()).unwrap_or("");
            let tl = args.get(2).ok_or_else(usage)?;
            e.get_timeline(tl)?; // must be a real timeline
            match sub {
                "up" => {
                    let mut allow = Vec::new();
                    for a in &args[3..] {
                        allow.push(tt_engine::gateway::AllowEntry::parse(a).map_err(ge)?);
                    }
                    let p = tt_engine::gateway::up(tl, &allow).map_err(ge)?;
                    println!("gateway up for {tl}: namespace {} ({} -> {})", p.ns, p.trial_ip, p.host_ip);
                    println!("allowed destinations: {}", if allow.is_empty() { "none".to_string() } else {
                        allow.iter().map(|a| a.to_string()).collect::<Vec<_>>().join(", ")
                    });
                }
                "down" => {
                    tt_engine::gateway::down(tl).map_err(ge)?;
                    println!("gateway down for {tl}");
                }
                "denied" => {
                    let list = tt_engine::gateway::harvest(tl).map_err(ge)?;
                    if list.is_empty() {
                        println!("no blocked connection attempts recorded for {tl}");
                    } else {
                        println!("blocked connection attempts from {tl}:");
                        for d in &list {
                            println!("  DENY {}", d.target());
                        }
                    }
                }
                "exec" => {
                    let split = args.iter().position(|a| a == "--").ok_or_else(usage)?;
                    let cmd_args = &args[split + 1..];
                    if cmd_args.is_empty() {
                        return Err(usage());
                    }
                    let code = tt_engine::gateway::exec_in(tl, cmd_args).map_err(ge)?;
                    std::process::exit(code);
                }
                _ => return Err(usage()),
            }
        }
        
        "docker" => {
            let usage = || tt_engine::EngineError(
                "usage: tl docker list [timeline] | capture <container> <tag> | capture-volume <volume> | restore-volume <content-hash> <timeline> <new-volume>".into(),
            );
            let docker_error = |error: tt_engine::docker::DockerError| {
                tt_engine::EngineError(error.to_string())
            };
            match args.get(1).map(|arg| arg.as_str()) {
                Some("list") => {
                    let timeline = args.get(2).map(|arg| arg.as_str());
                    let containers = tt_engine::docker::list_managed_containers(timeline)
                        .map_err(docker_error)?;
                    if containers.is_empty() {
                        println!("no TemporalTrail-managed containers found");
                    }
                    for container in containers {
                        println!(
                            "{}  {}  {}  {}  timeline={}",
                            container.id, container.name, container.image, container.state, container.timeline
                        );
                    }
                }
                Some("capture") => {
                    let container = args.get(2).ok_or_else(usage)?;
                    let tag = args.get(3).ok_or_else(usage)?;
                    let capture = tt_engine::docker::capture_container(container, tag)
                        .map_err(docker_error)?;
                    println!(
                        "captured container {} as image {}",
                        capture.container_name, capture.image_reference
                    );
                    println!("image id: {}", capture.image_id);
                    println!("configuration saved: {} bytes", capture.inspect_json.len());
                }
                Some("capture-volume") => {
                    let volume = args.get(2).ok_or_else(usage)?;
                    let archive_store = home.join("docker-volumes");
                    let capture = tt_engine::docker::capture_volume(volume, &archive_store)
                        .map_err(docker_error)?;
                    println!(
                        "captured volume {} ({} bytes)",
                        capture.volume_name, capture.size_bytes
                    );
                    println!("content hash: {}", capture.content_hash);
                    println!("archive: {}", capture.archive_path.display());
                    if capture.already_stored {
                        println!("identical archive already stored; nothing new written");
                    }
                }
                Some("restore-volume") => {
                    let content_hash = args.get(2).ok_or_else(usage)?;
                    let timeline = args.get(3).ok_or_else(usage)?;
                    let volume = args.get(4).ok_or_else(usage)?;
                    let archive_store = home.join("docker-volumes");
                    let restored = tt_engine::docker::restore_volume(
                        content_hash,
                        &archive_store,
                        timeline,
                        volume,
                    )
                    .map_err(docker_error)?;
                    println!(
                        "restored archive {} into new volume {} for timeline {}",
                        restored.content_hash, restored.volume_name, restored.timeline
                    );
                }
                _ => return Err(usage()),
            }
        }

        "promote" => {
            let node_ref = args.get(1).ok_or_else(|| tt_engine::EngineError(
                "usage: tl promote <node-ref> [--confirm-superseding-effects]".into(),
            ))?;
            let node_id = e.resolve(&NodeRef::parse(node_ref))?;
            let confirm = args.iter().any(|a| a == "--confirm-superseding-effects");
            let r = e.promote(node_id, confirm)?;
            println!("promotion #{} committed", r.promotion_id);
            println!("MAIN divergence ancestor: n{}", r.main_divergence_ancestor);
            println!("MAIN HEAD n{} -> n{}", r.superseded_main_head, r.promoted_node_id);
            if r.superseding_interactions_confirmed > 0 {
                println!(
                    "note: {} superseded external interaction(s) confirmed, not reverted",
                    r.superseding_interactions_confirmed
                );
            }
        }

        "discard" => {
            let usage = || tt_engine::EngineError(
                "usage: tl discard <timeline-name> | tl discard --all [--yes]".into(),
            );
            let target = args.get(1).ok_or_else(usage)?;
            if target.as_str() == "--all" {
                let trial_names = e.trial_timeline_names()?;
                if trial_names.is_empty() {
                    println!("no trial timelines to discard (MAIN is never discarded)");
                    return Ok(());
                }
                println!(
                    "this will discard {} timeline(s): {}",
                    trial_names.len(),
                    trial_names.join(", ")
                );
                println!("MAIN is not affected. Node history is kept.");
                if !args.iter().any(|arg| arg == "--yes") {
                    print!("type 'yes' to continue: ");
                    std::io::Write::flush(&mut std::io::stdout()).ok();
                    let mut answer = String::new();
                    std::io::stdin().read_line(&mut answer).ok();
                    if answer.trim() != "yes" {
                        println!("cancelled, nothing was discarded");
                        return Ok(());
                    }
                }
                for report in e.discard_all_trial_timelines()? {
                    print_discard_report(&report);
                }
            } else {
                let report = e.discard(target)?;
                print_discard_report(&report);
            }
        }

        other => {
            eprintln!("unknown command: {other}");
            eprintln!(
                "commands: init status timelines enter leave checkpoint fork switch log diff \
                 validate allow deny promote discard"
            );
            std::process::exit(2);
        }
    }
    Ok(())
}

fn flag_value(args: &[String], flag: &str) -> Option<String> {
    args.iter()
        .position(|a| a == flag)
        .and_then(|i| args.get(i + 1))
        .cloned()
}

fn parse_node_id(s: Option<&String>) -> Result<i64> {
    let s = s.ok_or_else(|| tt_engine::EngineError("missing node id".into()))?;
    let s = s.strip_prefix('n').unwrap_or(s);
    s.parse::<i64>()
        .map_err(|_| tt_engine::EngineError(format!("invalid node id: {s}")))
}

fn print_discard_report(report: &tt_engine::DiscardReport) {
    println!("timeline '{}' discarded.", report.timeline_name);
    println!("internal state: discarded.");
    println!(
        "external interactions: {} allowed, {} denied",
        report.allowed, report.denied
    );
    println!("these external effects cannot be automatically reverted.");
}