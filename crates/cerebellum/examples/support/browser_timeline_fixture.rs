use super::*;

pub const HTML: &str = r##"<!doctype html><meta charset="utf-8"><title>Local timeline</title>
<main><h1>Local home timeline</h1><button>Compose</button><section id="timeline"></section>
<section id="embeds"></section><section id="large"></section></main>
<script>
window.fill = count => { large.replaceChildren(); const fragment=document.createDocumentFragment(); for(let i=0;i<count;i++){const row=document.createElement('div');row.textContent='Timeline metadata '+i;fragment.append(row)} large.append(fragment);return count; };
window.virtualize = ms => { clearInterval(window.listTimer);timeline.replaceChildren();for(let i=0;i<80;i++){const row=document.createElement('article');row.innerHTML='<button>Local post '+i+'</button><p>Timeline entry</p>';timeline.append(row)}window.listTimer=setInterval(()=>{timeline.firstChild.remove();const row=document.createElement('article');row.innerHTML='<button>New local post '+performance.now()+'</button><p>Timeline entry</p>';timeline.append(row)},ms);return true; };
window.frames = hidden => { clearInterval(window.frameTimer);embeds.replaceChildren();const loaded=[];for(let i=0;i<5;i++){const frame=document.createElement('iframe');loaded.push(new Promise(r=>frame.onload=r));frame.title='Local embed '+i;frame.src='http://localhost:'+location.port+'/timeline-frame?'+i;if(hidden)frame.style.display='none';embeds.append(frame)}window.framesReady=Promise.all(loaded).then(()=>true);return true; };
window.churnFrames = () => { window.frameTimer=setInterval(()=>{embeds.firstChild.remove();const frame=document.createElement('iframe');frame.title='Replacing local embed';frame.src='http://localhost:'+location.port+'/timeline-frame?'+performance.now();embeds.append(frame)},100);return true; };
window.ready = navigator.serviceWorker.register('/timeline-worker.js').then(()=>navigator.serviceWorker.ready).then(()=>true);
</script>"##;

pub const CHILD: &str = r#"<!doctype html><meta charset="utf-8"><title>Local embed</title><main><h2>Embedded local content</h2><button>Embed action</button></main>"#;
pub const WORKER: &str = "self.addEventListener('install',()=>self.skipWaiting());self.addEventListener('activate',event=>event.waitUntil(self.clients.claim()));self.addEventListener('fetch',()=>{});";

async fn snapshots(planes: &Planes, corr: &mut u64, pipe: &Pipe, name: &str) -> Result<(), String> {
    for mode in ["actionable", "ax", "dom_full"] {
        {
            let mut state = pipe.0.lock().unwrap();
            state.timings.clear();
            state.history.clear();
        }
        let start = Instant::now();
        let reply = invoke(
            planes,
            corr,
            "browser.snapshot",
            json!({"mode":mode,"max_bytes":5000}),
        )
        .await?;
        {
            let state = pipe.0.lock().unwrap();
            let mut groups = std::collections::BTreeMap::<&str, (usize, u128, u128)>::new();
            for (method, ms) in &state.timings {
                let group = groups.entry(method).or_default();
                group.0 += 1;
                group.1 += ms;
                group.2 = group.2.max(*ms);
            }
            let pending: Vec<_> = state.trace.values().map(|c| c["method"].clone()).collect();
            println!("TIMELINE {name}/{mode}: elapsed_ms={} outcome={} detail={} truncated={} pending={pending:?}", start.elapsed().as_millis(), reply["outcome"], reply["detail"], reply["truncated"]);
            println!("CDP TIMINGS {name}/{mode} (commands,total_ms,max_ms): {groups:?}");
            let errors: Vec<_> = state
                .history
                .iter()
                .filter(|(_, response)| response.get("error").is_some())
                .collect();
            println!("CDP ERRORS {name}/{mode}: {errors:?}");
        }
        if reply["outcome"] == "internal_error" && reply["detail"]["reason_code"] == "cdp_failure" {
            if reply["detail"]["step"].as_str().is_none() {
                return Err(format!("snapshot omitted its failing step: {reply}"));
            }
            let start = Instant::now();
            let screenshot = invoke(planes, corr, "browser.screenshot", json!({})).await?;
            println!(
                "TIMELINE SCREENSHOT {name}/{mode}: elapsed_ms={} outcome={}",
                start.elapsed().as_millis(),
                screenshot["outcome"]
            );
            check_ok(&screenshot)?;
        }
    }
    Ok(())
}

pub async fn exercise(planes: &Planes, pipe: &Pipe, origin: &str) -> Result<(), String> {
    let mut corr = 0;
    let launched = invoke(planes, &mut corr, "browser.launch", json!({})).await?;
    check_outcome(&launched, "launched")?;
    let result = async {
        check_ok(&invoke(planes, &mut corr, "browser.navigate", json!({"url":format!("{origin}/timeline"),"intent":"open loopback timeline","wait":"settle","severity":{"tier":1,"credential":false,"financial":false}})).await?)?;
        println!("Chrome: {}", pipe.evaluate("navigator.userAgent")?);
        let ready = pipe.command("Runtime.evaluate",json!({"expression":"window.ready","awaitPromise":true,"returnByValue":true}))?;
        println!("SERVICE WORKER READY: {ready}");
        snapshots(planes, &mut corr, pipe, "worker_idle").await?;
        pipe.evaluate("window.virtualize(20);true")?;
        snapshots(planes, &mut corr, pipe, "virtualized_20ms").await?;
        pipe.evaluate("clearInterval(window.listTimer);window.fill(20000)")?;
        snapshots(planes, &mut corr, pipe, "large_20000").await?;
        pipe.evaluate("window.fill(0);window.frames(false)")?;
        // Wait for the iframe load events before reading their documents.
        pipe.command("Runtime.evaluate", json!({"expression":"window.framesReady","awaitPromise":true,"returnByValue":true}))?;
        snapshots(planes, &mut corr, pipe, "five_oopifs").await?;
        pipe.evaluate("window.virtualize(20);window.fill(20000)")?;
        snapshots(planes, &mut corr, pipe, "combined").await?;
        pipe.evaluate("window.fill(0);clearInterval(window.listTimer);[...embeds.children].forEach(f=>f.style.display='none');true")?;
        snapshots(planes, &mut corr, pipe, "hidden_oopifs").await?;
        pipe.evaluate("window.frames(false);window.churnFrames()")?;
        snapshots(planes, &mut corr, pipe, "detaching_oopifs").await?;
        pipe.evaluate("clearInterval(window.frameTimer);embeds.replaceChildren();timeline.replaceChildren();true")?;
        let recovered = invoke(planes, &mut corr, "browser.snapshot", json!({"max_bytes":5000})).await?;
        println!("TIMELINE RECOVERY: {recovered}");
        check_ok(&recovered)?;
        println!("LOCAL TIMELINE SUMMARY: 21 diagnostic snapshots, 1 recovery check");
        Ok(())
    }.await;
    let closed = invoke(
        planes,
        &mut corr,
        "browser.close",
        json!({"browser_session_id":launched["browser_session_id"]}),
    )
    .await?;
    check_outcome(&closed, "closed")?;
    result
}
