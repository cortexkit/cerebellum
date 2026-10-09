use super::*;

pub const HTML: &str = r##"<!doctype html><meta charset="utf-8"><title>Styled checkbox fixture</title>
<style>
body { margin:32px; font:16px sans-serif; } .long { height:450px; }
label.option { display:block; position:relative; width:500px; padding:16px 8px; }
.box { display:inline-block; width:18px; height:18px; border:2px solid; vertical-align:middle; margin-right:12px; }
input:checked + .box { background:green; }
input.hidden { position:absolute; width:0; height:0; opacity:0; }
input.none { appearance:none; width:20px; height:20px; position:absolute; opacity:0; }
input.overlay { position:absolute; width:20px; height:20px; }
</style>
<a href="#main">Skip to content</a><header id="letters"></header>
<main id="main"><form><h1>Create a local App</h1><label>Description<input id="description" aria-label="Description"></label><div id="status"></div>
<section class="long"><h2>General settings</h2><label>App name<input></label></section>
<section class="long"><h2>Callback settings</h2><label>Callback URL<input></label></section>
<div id="options">
<label class="option" id="hidden-label"><input id="hidden" class="hidden" type="checkbox"><span class="box"></span>Request user authorization during installation</label>
<label class="option" id="none-label"><input id="none" class="none" type="checkbox"><span class="box"></span>Appearance none</label>
<label class="option" id="overlay-label"><input id="overlay" class="overlay" type="checkbox"><span class="box" style="position:relative;background:white"></span>Overlaid checkbox</label>
<input id="external" class="hidden" type="checkbox"><label class="option" id="external-label" for="external"><span class="box"></span>External label</label>
</div></form></main>
<script>
// Narrow, wrapping text produces one inline accessibility layout fragment per letter.
for(let i=0;i<16;i++){ const p=document.createElement('p'); p.style.cssText='margin:0;width:1ch;word-break:break-all'; p.textContent='Skip to content'; document.getElementById('letters').append(p); }
const statusEl=document.getElementById('status'), optionsEl=document.getElementById('options');
description.addEventListener('input',()=>{ statusEl.replaceChildren(...['Description changed','Validation complete','Ready'].map(text=>{const p=document.createElement('p');p.textContent=text;return p})); optionsEl.innerHTML=optionsEl.innerHTML; });
</script>"##;

fn ax_ref(snapshot: &Value, role: &str, name: &str) -> Result<String, String> {
    snapshot["state_text"]
        .as_str()
        .unwrap_or("")
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .find(|node| {
            node["role"] == role && node["name"].as_str().is_some_and(|n| n.contains(name))
        })
        .and_then(|node| node["ref"].as_str().map(str::to_string))
        .ok_or_else(|| format!("missing {role} {name}"))
}
fn checkbox_ref(snapshot: &Value, name: &str) -> Result<String, String> {
    ax_ref(snapshot, "checkbox", name)
}

async fn click(
    planes: &Planes,
    corr: &mut u64,
    snapshot: &Value,
    reference: &str,
) -> Result<Value, String> {
    invoke(planes, corr, "browser.click", json!({"ref":reference,"snapshot_id":snapshot["snapshot_id"],"intent":"toggle local checkbox","severity":{"tier":2,"credential":false,"financial":false}})).await
}

pub async fn exercise(planes: &Planes, pipe: &Pipe, origin: &str) -> Result<(), String> {
    let mut corr = 0;
    let launched = invoke(planes, &mut corr, "browser.launch", json!({})).await?;
    check_outcome(&launched, "launched")?;
    let result = async {
        check_ok(&invoke(planes, &mut corr, "browser.navigate", json!({"url":format!("{origin}/click"),"intent":"open loopback checkbox fixture","wait":"settle","severity":{"tier":2,"credential":false,"financial":false}})).await?)?;
        println!("Chrome: {}", pipe.evaluate("navigator.userAgent")?);
        let mut passed = true;
        let snapshot = invoke(planes, &mut corr, "browser.snapshot", json!({"mode":"ax","max_bytes":12000})).await?;
        check_ok(&snapshot)?;
        let text = snapshot["state_text"].as_str().unwrap_or("");
        passed &= table_row("ax_budget_reaches_checkbox", text.contains("\"role\":\"checkbox\"") && !text.contains("InlineTextBox"), &json!({"bytes":text.len(),"checkbox_reached":text.contains("\"role\":\"checkbox\""),"inline_rows":text.matches("InlineTextBox").count()}));
        let snapshot = invoke(planes, &mut corr, "browser.snapshot", json!({"mode":"ax","max_bytes":65536})).await?;
        for (name, id, test) in [("Request user authorization", "hidden", "hidden_checkbox_toggles"), ("Appearance none", "none", "appearance_none_toggles"), ("Overlaid checkbox", "overlay", "overlaid_checkbox_toggles"), ("External label", "external", "external_label_toggles")] {
            let reply = click(planes, &mut corr, &snapshot, &checkbox_ref(&snapshot, name)?).await?;
            let checked = pipe.evaluate(&format!("document.getElementById('{id}').checked"))?;
            passed &= table_row(test, reply["outcome"] == "ok" && checked == true, &json!({"checked":checked,"reply":reply}));
        }
        // The label's text ref classifies to its input, but its visible label is the mouse target.
        let label_ref = ax_ref(&snapshot, "StaticText", "Request user authorization")?;
        let reply = click(planes, &mut corr, &snapshot, &label_ref).await?;
        let checked = pipe.evaluate("document.getElementById('hidden').checked")?;
        passed &= table_row("label_click_toggles", reply["outcome"] == "ok" && checked == false, &json!({"checked":checked,"reply":reply}));
        pipe.evaluate("document.getElementById('hidden-label').scrollIntoView({block:'center'}); true")?;
        let screenshot = invoke(planes, &mut corr, "browser.screenshot", json!({})).await?;
        check_ok(&screenshot)?;
        let point = pipe.evaluate("(()=>{const r=document.querySelector('#hidden-label .box').getBoundingClientRect();return [Math.round(r.x+r.width/2),Math.round(r.y+r.height/2)]})()")?;
        println!("POINT READBACK: {}", pipe.evaluate("(()=>{const r=document.querySelector('#hidden-label .box').getBoundingClientRect(); const e=document.elementFromPoint(r.x+r.width/2,r.y+r.height/2);return {scrollY,innerWidth,innerHeight,point:[r.x+r.width/2,r.y+r.height/2],hit:e?.outerHTML,viewport:{x:visualViewport.offsetLeft,y:visualViewport.offsetTop,scale:visualViewport.scale}}})()")?);
        let metrics = pipe.command("Page.getLayoutMetrics", json!({}))?;
        println!("POINT METRICS: {}", metrics["result"]["cssVisualViewport"]);
        for (source, x, y) in [("viewport", point[0].as_i64().unwrap(), point[1].as_i64().unwrap()), ("document", point[0].as_i64().unwrap(), point[1].as_i64().unwrap() + pipe.evaluate("scrollY")?.as_i64().unwrap())] {
            println!("POINT HIT {source}: {}", pipe.command("DOM.getNodeForLocation", json!({"x":x,"y":y,"includeUserAgentShadowDOM":true}))?);
        }
        let reply = invoke(planes, &mut corr, "browser.click_point", json!({"snapshot_id":screenshot["snapshot_id"],"x_px":point[0],"y_px":point[1],"image_width_px":screenshot["image_width_px"],"image_height_px":screenshot["image_height_px"],"intent":"toggle local styled box","severity":{"tier":2,"credential":false,"financial":false}})).await?;
        let checked = pipe.evaluate("document.getElementById('hidden').checked")?;
        passed &= table_row("point_classification_toggles", reply["outcome"] == "ok" && checked == true, &json!({"checked":checked,"reply":reply}));
        let screenshot = invoke(planes, &mut corr, "browser.screenshot", json!({})).await?;
        check_ok(&screenshot)?;
        let point = pipe.evaluate("(()=>{const r=document.querySelector('#hidden-label').getBoundingClientRect();return [Math.round(r.x+r.width/2),Math.round(r.y+r.height/2)]})()")?;
        let reply = invoke(planes, &mut corr, "browser.click_point", json!({"snapshot_id":screenshot["snapshot_id"],"x_px":point[0],"y_px":point[1],"image_width_px":screenshot["image_width_px"],"image_height_px":screenshot["image_height_px"],"intent":"toggle local label text","severity":{"tier":2,"credential":false,"financial":false}})).await?;
        let checked = pipe.evaluate("document.getElementById('hidden').checked")?;
        passed &= table_row("point_label_toggles", reply["outcome"] == "ok" && checked == false, &json!({"checked":checked,"reply":reply}));
        let old_ref = checkbox_ref(&snapshot, "Request user authorization")?;
        let typed = invoke(planes, &mut corr, "browser.type", json!({"ref":ax_ref(&snapshot,"textbox","Description")?,"text":"new description"})).await?;
        check_ok(&typed)?;
        let reply = click(planes, &mut corr, &snapshot, &old_ref).await?;
        passed &= table_row("replaced_node_is_stale", reply["outcome"] == "stale_snapshot" || reply.pointer("/detail/classification_unavailable") == Some(&json!("target_not_in_document")), &reply);
        let fresh = invoke(planes, &mut corr, "browser.snapshot", json!({"mode":"ax","max_bytes":65536})).await?;
        let new_ref = checkbox_ref(&fresh,"Request user authorization")?;
        passed &= table_row("typing_shifts_later_refs", old_ref != new_ref, &json!({"old":old_ref,"fresh":new_ref}));
        println!("LOCAL CLICK SUMMARY: 10 checks");
        if passed { Ok(()) } else { Err("local checkbox checks failed".into()) }
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
