const el=function(id){return document.getElementById(id)};let data=[];
function render(){
 const q=el("q").value.toLowerCase().trim(),t=el("type").value;
 const rows=data.filter(function(x){return (!q||[x.title,x.project,x.vulnerability_class,x.source_name].join(" ").toLowerCase().includes(q))&&(!t||x.record_type===t)});
 el("stats").innerHTML=[["Records",data.length],["Critical",data.filter(function(x){return x.severity==="Critical"}).length],["Bounties",data.filter(function(x){return x.reward_amount!=null}).length]].map(function(a){return "<div class=\"stat\"><b>"+a[1]+"</b><div class=\"muted\">"+a[0]+"</div></div>"}).join("");
 el("results").innerHTML=rows.slice(0,100).map(function(x){return "<article class=\"card\"><div class=\"title\">"+x.case_id+" — "+x.title+"</div><div class=\"meta\"><span class=\"tag\">"+x.record_type+"</span><span class=\"tag\">Critical</span>"+(x.project?"<span class=\"tag\">"+x.project+"</span>":"")+(x.reward_amount?"<span class=\"tag\">$"+Number(x.reward_amount).toLocaleString()+"</span>":"")+"</div><p class=\"muted\">"+(x.vulnerability_class||"Class pending normalization")+"</p></article>"}).join("")
}
fetch("../datasets/reports.json").then(function(r){return r.json()}).then(function(x){data=x;render()});
["q","type"].forEach(function(id){el(id).addEventListener("input",render);});