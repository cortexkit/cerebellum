/// A loopback-only permissions page: controls persist while selected labels
/// are inserted, and menu buttons do not exist until their dropdown is opened.
pub const HTML: &str = r#"<!doctype html><title>Permissions fixture</title>
<style>li {margin: 4px} button {font-size: 14px}</style>
<iframe id="ref-frame" title="Embedded control" src="/ref-frame"></iframe>
<main aria-label="Permissions"><ul aria-label="Permission list" id="permissions"></ul></main>
<script>
for (let i = 0; i < 40; i++) {
 const name = 'Permission ' + String(i).padStart(2, '0');
 const item = document.createElement('li'); item.setAttribute('aria-label', name);
 item.innerHTML = '<button type="button" aria-label="Access: '+name+'">Access: none</button>';
 const access = item.firstChild; access.id = 'access-'+i;
 access.onclick = () => {
  const old = item.querySelector('[role=menu]'); if (old) { old.remove(); return; }
  const menu = document.createElement('div'); menu.setAttribute('role', 'menu');
  const choice = document.createElement('button'); choice.type = 'button';
  choice.textContent = 'Read: '+name; choice.setAttribute('role','menuitem');
  choice.onclick = () => {
   menu.remove(); const selected = document.createElement('span');
   selected.textContent = 'Selected'; item.insertBefore(selected, access);
   access.textContent = 'Access: read';
  };
  menu.append(choice); item.append(menu);
 };
 document.getElementById('permissions').append(item);
}
const remove = document.createElement('button'); remove.type='button';
remove.textContent='Remove Permission 39'; remove.onclick=()=>document.getElementById('access-39').parentNode.remove();
document.body.append(remove);
</script>"#;

pub const CHILD: &str = r#"<!doctype html><button type="button" aria-label="Frame action" onclick="document.body.dataset.clicked='yes'">Frame action</button>"#;

use super::{check_ok, check_outcome, invoke, reference, Pipe, Planes};
use serde_json::{json, Value};

async fn click(planes: &Planes, corr: &mut u64, snapshot: &Value, reference: &str) -> Result<Value, String> {
    invoke(planes, corr, "browser.click", json!({"ref":reference,"snapshot_id":snapshot["snapshot_id"],"intent":"choose a local fixture permission","severity":{"tier":2,"credential":false,"financial":false}})).await
}

pub async fn exercise(planes: &Planes, pipe: &Pipe, origin: &str) -> Result<(), String> {
    let mut corr = 0;
    let launched = invoke(planes, &mut corr, "browser.launch", json!({})).await?;
    check_outcome(&launched, "launched")?;
    let result = async {
        let mut totals = [0usize; 2];
        for (strategy, total) in totals.iter_mut().enumerate() {
            let navigated = invoke(planes, &mut corr, "browser.navigate", json!({"url":format!("{origin}/dropdowns"),"intent":"open loopback permissions fixture","wait":"settle","severity":{"tier":1,"credential":false,"financial":false}})).await?;
            check_ok(&navigated)?;
            if strategy == 0 { println!("Chrome: {}", pipe.evaluate("navigator.userAgent")?); }
            let seed = invoke(planes, &mut corr, "browser.snapshot", json!({"role_filter":["button"]})).await?;
            check_ok(&seed)?;
            let later = reference(&seed, "button Access: Permission 39")?;
            if strategy == 0 {
                let framed = reference(&seed, "Frame action")?;
                pipe.evaluate("document.getElementById('ref-frame').contentWindow.history.pushState({}, '', '/ref-frame#same'); true")?;
                check_ok(&click(planes, &mut corr, &seed, &framed).await?)?;
                if pipe.evaluate("document.getElementById('ref-frame').contentDocument.body.dataset.clicked")? != "yes" { return Err("iframe old click did not land".into()); }
                let same = invoke(planes, &mut corr, "browser.snapshot", json!({"zoom":framed})).await?;
                check_ok(&same)?;
                if reference(&same, "Frame action")? != framed { return Err("iframe pushState changed its ref".into()); }
                pipe.command("Runtime.evaluate", json!({"expression":"new Promise(resolve => { const frame = document.getElementById('ref-frame'); frame.onload = () => resolve(true); frame.src = '/ref-frame?reload'; })", "awaitPromise":true, "returnByValue":true}))?;
                check_outcome(&click(planes, &mut corr, &same, &framed).await?, "stale_snapshot")?;
                let moved = invoke(planes, &mut corr, "browser.snapshot", json!({"zoom":framed})).await?;
                check_outcome(&moved, "stale_snapshot")?;
                println!("Iframe pushState / reload   | PASS | old click works / old refs stale");
            }
            let list = reference(&seed, "list Permission list")?;
            for item in 0..4 {
                let name = format!("Permission {item:02}");
                let args = if strategy == 0 { json!({"zoom":list,"max_bytes":262144}) } else { json!({"text_filter":name,"role_filter":["button"]}) };
                let access = invoke(planes, &mut corr, "browser.snapshot", args).await?;
                check_ok(&access)?;
                *total += access["state_text"].as_str().ok_or("missing page text")?.len();
                let button = reference(&access, &format!("button Access: {name}"))?;
                check_ok(&click(planes, &mut corr, &access, &button).await?)?;
                let args = if strategy == 0 { json!({"zoom":list,"max_bytes":262144}) } else { json!({"text_filter":name,"role_filter":["menuitem"]}) };
                let menu = invoke(planes, &mut corr, "browser.snapshot", args).await?;
                check_ok(&menu)?;
                *total += menu["state_text"].as_str().ok_or("missing menu text")?.len();
                let choice = reference(&menu, &format!("menuitem Read: {name}"))?;
                check_ok(&click(planes, &mut corr, &menu, &choice).await?)?;
                if strategy == 1 && item == 0 {
                    // The older snapshot is still retained and its later button
                    // must survive the selected label inserted above it.
                    check_ok(&click(planes, &mut corr, &seed, &later).await?)?;
                    pipe.evaluate("document.getElementById('access-39').click(); true")?;
                    println!("Older snapshot click        | PASS | {later}");
                }
            }
            let after = invoke(planes, &mut corr, "browser.snapshot", json!({"text_filter":"Permission 39","role_filter":["button"]})).await?;
            check_ok(&after)?;
            let fresh = reference(&after, "button Access: Permission 39")?;
            if fresh != later { return Err(format!("later ref changed: {later} -> {fresh}")); }
            let text = after["state_text"].as_str().ok_or("missing filtered text")?;
            if text.lines().filter(|line| line.contains("button Access:")).count() != 1 || text.contains("Permission 38") {
                return Err(format!("filter showed unrelated items: {text}"));
            }
            println!("Stable later ref and filter | PASS | {fresh}");
            pipe.evaluate("document.getElementById('access-39').parentNode.remove(); true")?;
            let zoom = invoke(planes, &mut corr, "browser.snapshot", json!({"zoom":later})).await?;
            check_outcome(&zoom, "stale_snapshot")?;
            check_outcome(&click(planes, &mut corr, &after, &later).await?, "stale_snapshot")?;
            let remaining = invoke(planes, &mut corr, "browser.snapshot", json!({"text_filter":"Permission 38","role_filter":["button"]})).await?;
            if reference(&remaining, "button Access: Permission 38")? == later { return Err("removed ref was reassigned".into()); }
            println!("Removed ref zoom and click  | PASS | stale; no reassignment");
        }
        println!("Four dropdowns snapshot bytes: full-region={} filtered={} saved={} ({:.1}%)", totals[0], totals[1], totals[0]-totals[1], 100.0*(1.0-totals[1] as f64/totals[0] as f64));
        Ok(())
    }.await;
    let closed = invoke(planes, &mut corr, "browser.close", json!({"browser_session_id":launched["browser_session_id"]})).await?;
    check_outcome(&closed, "closed")?;
    result
}
