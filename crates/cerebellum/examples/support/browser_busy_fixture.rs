use super::*;

pub const HTML: &str = r##"<!doctype html><meta charset="utf-8"><title>Local event drawer</title>
<main><h1>Event details</h1><div id="row" onclick="window.clicked=(window.clicked||0)+1" style="padding:20px;width:300px">Open event text</div><section id="drawer"></section></main>
<script>
window.fill = count => { drawer.replaceChildren(); const fragment=document.createDocumentFragment(); for(let i=0;i<count;i++){const row=document.createElement('div');row.textContent='JSON field '+i+': value';fragment.append(row)} drawer.append(fragment); return count; };
window.block = ms => { setTimeout(()=>{const end=performance.now()+ms;while(performance.now()<end){}},0); return ms; };
window.stream = () => { window.timer=setInterval(()=>{const line=document.createElement('p');line.textContent='Streaming event '+performance.now();drawer.append(line)},100); return true; };
</script>"##;

async fn snapshot(planes: &Planes, corr: &mut u64, pipe: &Pipe, name: &str) -> Result<Value, String> {
    pipe.0.lock().unwrap().timings.clear();
    let start = Instant::now();
    let reply = invoke(planes, corr, "browser.snapshot", json!({"mode":"ax","max_bytes":5000})).await?;
    let state = pipe.0.lock().unwrap();
    let pending: Vec<_> = state.trace.values().map(|c| c["method"].clone()).collect();
    println!("BUSY PROBE {name}: elapsed_ms={} outcome={} detail={} pending={pending:?} truncated={}", start.elapsed().as_millis(), reply["outcome"], reply["detail"], reply["truncated"]);
    let mut groups = std::collections::BTreeMap::<&str, (usize, u128, u128)>::new();
    for (method, ms) in &state.timings { let group=groups.entry(method).or_default(); group.0+=1; group.1+=ms; group.2=group.2.max(*ms); }
    println!("CDP TIMINGS {name} (commands,total_ms,max_ms): {groups:?}");
    Ok(reply)
}

pub async fn exercise(planes: &Planes, pipe: &Pipe, origin: &str) -> Result<(), String> {
    let mut corr = 0;
    let launched = invoke(planes, &mut corr, "browser.launch", json!({})).await?;
    check_outcome(&launched, "launched")?;
    let result = async {
        check_ok(&invoke(planes, &mut corr, "browser.navigate", json!({"url":format!("{origin}/busy"),"intent":"open local event drawer","wait":"settle","severity":{"tier":1,"credential":false,"financial":false}})).await?)?;
        println!("Chrome: {}", pipe.evaluate("navigator.userAgent")?);
        let idle = snapshot(planes, &mut corr, pipe, "idle").await?;
        check_ok(&idle)?;
        let reference = reference(&idle,"Open event text")?;
        let arguments = json!({"ref":reference,"snapshot_id":idle["snapshot_id"],"intent":"open local log row by its text","severity":{"tier":2,"credential":false,"financial":false}});
        let clicked = invoke(planes,&mut corr,"browser.click",arguments.clone()).await?;
        check_ok(&clicked)?;
        let count = pipe.evaluate("window.clicked")?;
        if count != 1 { return Err(format!("text click did not activate row: {clicked}")); }
        println!("BUSY PROBE text_row_click: outcome={} clicked={count}",clicked["outcome"]);
        pipe.evaluate("(()=>{const r=row.getBoundingClientRect();const cover=document.createElement('div');cover.id='cover';cover.textContent='Local overlay';cover.style.cssText=`position:fixed;left:${r.x}px;top:${r.y}px;width:${r.width}px;height:${r.height}px;background:white;z-index:100`;document.body.append(cover);return true})()")?;
        let intercepted = invoke(planes,&mut corr,"browser.click",arguments).await?;
        check_outcome(&intercepted,"element_intercepted")?;
        let count = pipe.evaluate("window.clicked")?;
        if count != 1 { return Err("covered row was activated".into()); }
        println!("BUSY PROBE text_row_overlay: outcome={} clicked={count}",intercepted["outcome"]);
        pipe.evaluate("cover.remove(); true")?;
        pipe.evaluate("window.stream()")?;
        check_ok(&snapshot(planes, &mut corr, pipe, "stream_append_100ms").await?)?;
        pipe.evaluate("clearInterval(window.timer); window.fill(20000)")?;
        let huge = snapshot(planes, &mut corr, pipe, "20000_dom_rows").await?;
        check_ok(&huge)?;
        if huge["truncated"] != true || huge["refs_truncated"] != true { return Err(format!("huge snapshot did not report partial: {huge}")); }
        let huge_again = snapshot(planes, &mut corr, pipe, "same_20000_dom_rows").await?;
        check_ok(&huge_again)?;
        if huge_again["truncated"] != true { return Err("same huge page did not report partial".into()); }
        pipe.evaluate("window.fill(0); window.block(14000)")?;
        let busy = snapshot(planes, &mut corr, pipe, "main_thread_14000ms").await?;
        println!("BUSY REPLY {}", busy);
        check_outcome(&busy,"command_timeout")?;
        if busy["detail"]["step"] != "Page.getFrameTree" { return Err(format!("unexpected blocked step: {busy}")); }
        // Readback waits for the blocking script to finish without racing the driver.
        pipe.command_with_timeout("Runtime.evaluate",json!({"expression":"true","returnByValue":true}),Duration::from_secs(30))?;
        check_ok(&snapshot(planes, &mut corr, pipe, "idle_after_timeout").await?)?;
        println!("LOCAL BUSY SUMMARY: 6 snapshot observations, 2 text click checks");
        Ok(())
    }.await;
    let closed = invoke(planes, &mut corr, "browser.close", json!({"browser_session_id":launched["browser_session_id"]})).await?;
    check_outcome(&closed, "closed")?;
    result
}
