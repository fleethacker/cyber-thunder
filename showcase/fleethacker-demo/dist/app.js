'use strict';

const steps = [
  {kicker:'KNOW YOUR ENCLAVE',title:'Start with<br>what’s in scope.',description:'Bring Linux, Windows, network devices, containers and Kubernetes into one inventory. An operator explicitly controls what the system can touch.',evidence:['Shared inventory across five adapter families','Scope is explicit and enforced','Host-cluster discovery in the packaged deployment'],payoff:'One operational picture. A clearly defined boundary.',image:'assets/app-assets.jpg',alt:'Cyber Thunder asset inventory and discovery interface',route:'ASSETS'},
  {kicker:'EVIDENCE BEFORE EXPLANATION',title:'Find the risk.<br>Keep the source.',description:'Deterministic checks and imported scanner results become a common findings view. Trace a weakness back to its rule, host and evidence instead of asking a model to guess.',evidence:['STIG, CVE and ATT&CK references','Filter by host, severity, source and status','Scanner imports join current findings and reports'],payoff:'Spend less effort reconciling outputs. Keep the evidence in view.',image:'assets/app-findings.jpg',alt:'Cyber Thunder findings table showing cited configuration weaknesses and affected hosts',route:'FINDINGS'},
  {kicker:'THE HUMAN AUTHORITY GATE',title:'A clear proposal.<br>A human decision.',description:'See what is wrong, why it matters, what will change, what could break, and how to undo it. Approve or deny a specific library fix before it can be applied.',evidence:['Plain-language risk with cited sources','Impact and recovery plan shown before approval','Named operator; no arbitrary model-generated commands'],payoff:'The system does the correlation. The operator keeps the authority.',image:'assets/app-decisions.jpg',alt:'Cyber Thunder proposal card with evidence, impact, rollback plan and approve or deny controls',route:'DECISIONS'},
  {kicker:'VERIFY IT. RECORD IT. RECOVER IT.',title:'“Applied” isn’t<br>the finish line.',description:'Capture before-state, execute an approved fix and verify the result. Failed verification triggers restoration. Follow the action through the hash-chained audit record.',evidence:['Before-state captured before remediation','Verification and automatic rollback in the engine','Hash-chain verification and named audit events'],payoff:'A change is only useful when its outcome is known.',image:'assets/app-audit.jpg',alt:'Cyber Thunder audit trail showing verified hash chain and a timeline of operator and system events',route:'AUDIT TRAIL'},
  {kicker:'EVIDENCE FOR THE NEXT WATCH',title:'Close the loop.<br>Carry it forward.',description:'Keep commander reports, POA&Ms, checklists and target reports in searchable history. Reopen saved versions instead of reconstructing yesterday’s evidence.',evidence:['Search and filter saved report history','Download the saved version of the evidence','Queue report payloads for sync on reconnect'],payoff:'Give the next watch a defensible record, not another spreadsheet.',image:'assets/app-reports.jpg',alt:'Cyber Thunder reports interface with searchable saved report history and export options',route:'REPORTS'}
];

let stepIndex = 0;
const tabs = Array.from(document.querySelectorAll('[data-step]'));
const byId = id => document.getElementById(id);

function setStep(index, focusTab = false) {
  stepIndex = (index + steps.length) % steps.length;
  const step = steps[stepIndex];
  tabs.forEach((tab, i) => {
    tab.setAttribute('aria-selected', String(i === stepIndex));
    tab.tabIndex = i === stepIndex ? 0 : -1;
  });
  byId('tour-panel').setAttribute('aria-labelledby', 'tab-' + stepIndex);
  byId('tour-kicker').textContent = step.kicker;
  byId('tour-title').innerHTML = step.title;
  byId('tour-description').textContent = step.description;
  byId('tour-image').src = step.image;
  byId('tour-image').alt = step.alt;
  byId('tour-evidence').replaceChildren(...step.evidence.map(text => {
    const li = document.createElement('li'); li.textContent = text; return li;
  }));
  byId('tour-payoff').textContent = step.payoff;
  byId('tour-route').textContent = step.route;
  byId('tour-count').textContent = String(stepIndex + 1).padStart(2, '0') + ' / 05';
  if (focusTab) tabs[stepIndex].focus();
}
tabs.forEach(tab => tab.addEventListener('click', () => setStep(Number(tab.dataset.step))));
document.querySelector('.mission-tabs').addEventListener('keydown', event => {
  const keys = {ArrowRight: stepIndex + 1, ArrowLeft: stepIndex - 1, Home: 0, End: steps.length - 1};
  if (event.key in keys) {event.preventDefault(); setStep(keys[event.key], true);}
});
byId('tour-prev').addEventListener('click', () => setStep(stepIndex - 1));
byId('tour-next').addEventListener('click', () => setStep(stepIndex + 1));

const imageDialog = byId('image-dialog');
function openImage(src, caption) {
  byId('image-dialog-img').src = src;
  byId('image-dialog-img').alt = caption;
  byId('image-caption').textContent = caption;
  imageDialog.showModal();
}
function clickable(element, action) {
  element.addEventListener('click', action);
  if (element.tagName !== 'BUTTON') {
    element.addEventListener('keydown', event => {
      if (event.key === 'Enter' || event.key === ' ') {event.preventDefault(); action();}
    });
  }
}
document.querySelectorAll('[data-zoom]').forEach(element => clickable(element, () => openImage(element.dataset.zoom, element.dataset.caption)));
clickable(byId('tour-zoom'), () => openImage(steps[stepIndex].image, steps[stepIndex].alt + ' — real app screenshot, isolated demo range.'));
document.querySelectorAll('dialog').forEach(dialog => {
  dialog.querySelector('.dialog-close').addEventListener('click', () => dialog.close());
  dialog.addEventListener('click', event => {
    const rect = dialog.getBoundingClientRect();
    if (event.target === dialog && (event.clientX < rect.left || event.clientX > rect.right || event.clientY < rect.top || event.clientY > rect.bottom)) dialog.close();
  });
});

const stages = Array.from(document.querySelectorAll('[data-stage]'));
let simulation = 'pending';
function renderSimulation() {
  const status = byId('sim-status');
  const states = {
    pending: {text:'Waiting for your decision. No change has been made.', style:'', stages:['done','active','','']},
    approved: {text:'Approved. Before-state captured; simulated fix applied. Now verify the outcome.',style:'success',stages:['done','done','done','active']},
    denied: {text:'Denied. The host stays unchanged. In the app, your decision is retained in the audit log.',style:'denied',stages:['done','stopped','','']},
    verified: {text:'Verified. The simulated check passed and the fix is retained. Evidence closes the loop.',style:'success',stages:['done','done','done','done']},
    restored: {text:'Verification failed. Before-state restored automatically. The simulated host is back to its original configuration.',style:'restored',stages:['done','done','done','done']}
  };
  const state = states[simulation];
  status.textContent = state.text;
  status.className = 'sim-status ' + state.style;
  byId('sim-actions').hidden = simulation !== 'pending';
  byId('verify-options').hidden = simulation !== 'approved';
  stages.forEach((stage,i) => stage.className = state.stages[i]);
}
byId('sim-approve').addEventListener('click', () => {simulation = 'approved'; renderSimulation(); byId('sim-pass').focus();});
byId('sim-deny').addEventListener('click', () => {simulation = 'denied'; renderSimulation(); byId('sim-reset').focus();});
byId('sim-pass').addEventListener('click', () => {simulation = 'verified'; renderSimulation(); byId('sim-reset').focus();});
byId('sim-fail').addEventListener('click', () => {simulation = 'restored'; renderSimulation(); byId('sim-reset').focus();});
byId('sim-reset').addEventListener('click', () => {simulation = 'pending'; renderSimulation(); byId('sim-approve').focus();});
renderSimulation();

const briefing = [
  {kicker:'01 / THE MISSION',title:'The link drops.<br>The mission doesn’t.',description:'Cyber Thunder helps an isolated enclave turn scanner findings into approved, verified, reversible fixes—with a human in authority.',line:'Tools detect. AI explains. A Sailor decides.',note:'Open with the operational problem: the same small team has to correlate new vulnerabilities, act safely and leave evidence—even when reachback is limited.',image:'assets/app-commander.jpg',alt:'Actual Cyber Thunder commander dashboard'},
  {kicker:'02 / THE BOUNDARY',title:'Know the enclave.<br>Define the scope.',description:'One inventory brings Linux, Windows, Cisco, container and Kubernetes assets into the same workflow. Discovery does not grant unlimited authority.',line:'Explicit scope is the boundary around every action.',note:'Point to the asset inventory and scope controls. Distinguish simulated range assets from real demo targets. Never describe the prototype as an operationally authorized deployment.',image:'assets/app-assets.jpg',alt:'Actual Cyber Thunder inventory with in-scope range assets'},
  {kicker:'03 / THE EVIDENCE',title:'Find the weakness.<br>Keep the citation.',description:'Deterministic checks and scanner imports produce a common findings view. Local explanations add context; they do not invent detection results.',line:'Evidence first. Explanation second.',note:'Show a rule identifier, severity and affected host. Describe the reduction in manual handoffs as the value hypothesis; do not claim unmeasured hours saved.',image:'assets/app-findings.jpg',alt:'Actual Cyber Thunder cited findings table'},
  {kicker:'04 / THE HUMAN',title:'The system proposes.<br>The operator decides.',description:'A decision card explains the risk, the exact proposed change, potential disruption and the rollback plan. A named person approves or denies.',line:'No arbitrary commands from model output.',note:'Pause here. Ask the judge: would you approve this change? The page’s operator simulation demonstrates both choices without changing the deployed app.',image:'assets/app-decisions.jpg',alt:'Actual Cyber Thunder remediation decision card'},
  {kicker:'05 / THE OUTCOME',title:'Verify the change.<br>Prove the record.',description:'Capture before-state, apply an approved library fix, then verify. Failed verification triggers rollback. Hash-chained events make the action history inspectable.',line:'The finish line is a known outcome.',note:'Point to the chain-verified result. Explain that a kill switch and scope enforcement are implemented controls, and that operational authorization still requires evaluation.',image:'assets/app-audit.jpg',alt:'Actual Cyber Thunder hash-chain verification and audit events'},
  {kicker:'06 / THE HANDOVER',title:'Give the next watch<br>a defensible record.',description:'Search saved commander reports, POA&Ms, checklists and target reports. Keep the recorded evidence and queue report payloads for sync on reconnect.',line:'The evidence survives the shift change.',note:'Show report history rather than a blank export screen. Emphasize immutable saved versions and the existing disconnected workflow, with scanner content staged in advance.',image:'assets/app-reports.jpg',alt:'Actual Cyber Thunder report history and exports'},
  {kicker:'07 / THE ASK',title:'A mission partner.<br>A representative range.',description:'The next step is a measured evaluation: confirm owners, baseline the current workflow, test representative systems, then define the authority and pilot criteria.',line:'30 days: own it. 60 days: measure it. 90 days: decide.',note:'Ask for a mission owner, a technical sponsor, operator time, representative test content and an isolated training enclave. Owners and authorization are to be confirmed.',image:'assets/app-mission.jpg',alt:'Actual Cyber Thunder guided mission workflow'}
];
let briefIndex = 0;
const briefDialog = byId('brief-dialog');
const dots = briefing.map((slide,index) => {
  const button = document.createElement('button');
  button.type = 'button';
  button.setAttribute('aria-label', 'Briefing slide ' + (index + 1));
  button.addEventListener('click', () => renderBrief(index));
  byId('brief-dots').append(button);
  return button;
});
function renderBrief(index) {
  briefIndex = Math.max(0, Math.min(briefing.length - 1,index));
  const slide = briefing[briefIndex];
  byId('brief-kicker').textContent = slide.kicker;
  byId('brief-title').innerHTML = slide.title;
  byId('brief-description').textContent = slide.description;
  byId('brief-line').textContent = slide.line;
  byId('brief-note').textContent = slide.note;
  byId('brief-image').src = slide.image;
  byId('brief-image').alt = slide.alt;
  byId('brief-progress').textContent = String(briefIndex + 1).padStart(2,'0') + ' / ' + String(briefing.length).padStart(2,'0');
  byId('brief-prev').disabled = briefIndex === 0;
  byId('brief-next').textContent = briefIndex === briefing.length - 1 ? 'Restart ↺' : 'Next →';
  dots.forEach((dot,i) => dot.setAttribute('aria-current',String(i === briefIndex)));
}
document.querySelectorAll('[data-brief]').forEach(button => button.addEventListener('click', () => {
  renderBrief(0); briefDialog.showModal();
}));
byId('brief-prev').addEventListener('click', () => renderBrief(briefIndex - 1));
byId('brief-next').addEventListener('click', () => renderBrief(briefIndex === briefing.length - 1 ? 0 : briefIndex + 1));
briefDialog.addEventListener('keydown', event => {
  if (event.key === 'ArrowRight') {event.preventDefault(); renderBrief(briefIndex + 1);}
  if (event.key === 'ArrowLeft') {event.preventDefault(); renderBrief(briefIndex - 1);}
  if (event.key === 'Home') {event.preventDefault(); renderBrief(0);}
  if (event.key === 'End') {event.preventDefault(); renderBrief(briefing.length - 1);}
});
