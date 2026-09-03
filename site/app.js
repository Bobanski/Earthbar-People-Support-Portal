// Earthbar HR Case Management — frontend v2 (Supabase email OTP)
// ============================================================================
// V2 BACKEND CONTRACT — the RPCs this frontend calls (see UPDATE_SPEC.md).
// Until the v2 migrations are deployed these fail; the UI shows a clear
// "backend not deployed yet" message instead of breaking.
//
//   submit_case_v2(p_intake_type, p_category, p_description, p_anonymous,
//                  p_location, p_relationship, p_role, p_contact_email,
//                  p_contact_phone, p_parties jsonb, p_manual bool, p_incident_date date)
//     -> json { case_id, ref, anonymous, claim_code, handler, external, route_reason }
//     p_parties: [{type:'employee'|'customer', id?, name?, role_in_case:'victim'|'subject'|
//                  'witness'(legacy)|'witness_firsthand'|'witness_secondhand'|'reporter'}]
//                 one element per person+role (multi-role = multiple elements);
//                 the new role values need migration 015 (widened check constraint)
//     Contact email/phone are stored on EVERY case (even anonymous) but are
//     server-side only — never selectable by the dashboard.
//   set_risk_level(p_case_id uuid, p_risk text)   -- 'Low'|'Medium'|'High'
//   set_policies(p_case_id uuid, p_policies text) -- realms & policies in question
//   close_case(p_case_id uuid, p_substantiated boolean, p_note text)
//     -- closing REQUIRES substantiated yes/no
//   mention_lookup(p_employee_id text)
//     -> json [{ref, state, role_in_case, created_at}]
//   Storage bucket 'evidence' — path: <case_id>/<filename>
//   Unchanged v1 RPCs: advance_state, post_handler_message, check_status,
//                      reporter_reply, app_is_admin, app_is_handler
// ============================================================================
import { createClient } from "https://cdn.jsdelivr.net/npm/@supabase/supabase-js@2.115.0/+esm";
import { REGIONS, DISTRICTS, storeOrg } from "./store_org.js";
import { makeZip } from "./minizip.js";

const cfg = window.EARTHBAR_CONFIG || {};
// --- SESSION POLICY ---------------------------------------------------------
// Default: sessionStorage + a 24h idle limit. Verified HR handlers may opt in
// to an absolute 30-day session on a private device. The 30-day deadline never
// slides with activity. Supabase's server-side time-box setting requires Pro,
// so this extra deadline is enforced and cleared in the browser; all database
// authorization remains server-side on every request.
const IDLE_LIMIT_MS = 24 * 60 * 60 * 1000;
const TRUST_WINDOW_MS = 30 * 24 * 60 * 60 * 1000;
const LAST_SEEN_KEY = "eb_hr_last_seen";
const PROJECT_REF = (cfg.SUPABASE_URL||"").split("//")[1]?.split(".")[0] || "portal";
const AUTH_STORAGE_KEY = `sb-${PROJECT_REF}-auth-token`;
const TRUSTED_DEVICE_KEY = `eb_hr_trusted_device:${PROJECT_REF}`;
const TRUST_SIGNOUT_PENDING_KEY = `eb_hr_trusted_signout:${PROJECT_REF}`;
const CROSS_TAB_SIGNOUT_KEY = `eb_hr_cross_tab_signout:${PROJECT_REF}`;
const ACTIVITY_WRITE_INTERVAL_MS = 30 * 1000;
const USER_ACTIVITY_EVENTS = ["pointerdown", "click", "keydown", "input", "change", "submit", "wheel"];
let lastActivityWriteAt = 0;
let idleSignOutPending = false;
let idleExpiryTimer = null;
let trustedExpiryTimer = null;
let trustedSessionDeadline = 0;
let stagedAuthValue = null;
let volatileLastSeenAt = 0;
let trustedSignOutPendingMemory = false;
let crossTabSignOutPending = false;

function readTrustedDevice(){
  try {
    const marker = localStorage.getItem(TRUSTED_DEVICE_KEY);
    const record = JSON.parse(marker || "null");
    if (!record || record.v !== 1 || typeof record.userId !== "string" ||
        !Number.isFinite(record.until) || record.until <= Date.now()) {
      if (marker || localStorage.getItem(AUTH_STORAGE_KEY)) stagePersistedSessionForSignOut();
      return null;
    }
    return record;
  } catch {
    stagePersistedSessionForSignOut();
    return null;
  }
}
function stagePersistedSessionForSignOut(){
  let raw = stagedAuthValue;
  try { raw = localStorage.getItem(AUTH_STORAGE_KEY) || raw; } catch {}
  if (raw) {
    stagedAuthValue = raw;
    trustedSignOutPendingMemory = true;
    try { sessionStorage.setItem(AUTH_STORAGE_KEY, raw); sessionStorage.setItem(TRUST_SIGNOUT_PENDING_KEY, "1"); } catch {}
  }
  try { localStorage.removeItem(TRUSTED_DEVICE_KEY); localStorage.removeItem(AUTH_STORAGE_KEY); } catch {}
}
function clearTrustedDevice(){
  trustedSessionDeadline = 0;
  clearTimeout(trustedExpiryTimer); trustedExpiryTimer = null;
  try { localStorage.removeItem(TRUSTED_DEVICE_KEY); localStorage.removeItem(AUTH_STORAGE_KEY); } catch {}
}
function clearAllAuthStorage(){
  clearTrustedDevice();
  stagedAuthValue = null;
  trustedSignOutPendingMemory = false;
  try { sessionStorage.removeItem(TRUST_SIGNOUT_PENDING_KEY); sessionStorage.removeItem(AUTH_STORAGE_KEY); } catch {}
}
function publishCrossTabSignOut(){
  try { localStorage.setItem(CROSS_TAB_SIGNOUT_KEY, `${Date.now()}:${Math.random()}`); } catch {}
}
async function acceptCrossTabSignOut(){
  if (crossTabSignOutPending) return;
  crossTabSignOutPending = true;
  clearAllManualDrafts();
  resetSessionState();
  activeUserId = null;
  session = null;
  clearAllAuthStorage();
  render();
  try { await sb.auth.signOut({ scope:"local" }); } catch {}
  finally { clearAllAuthStorage(); crossTabSignOutPending = false; }
}
function demoteTrustedSession(){
  let raw = stagedAuthValue;
  try { raw = localStorage.getItem(AUTH_STORAGE_KEY) || raw; } catch {}
  if (raw) {
    stagedAuthValue = raw;
    try { sessionStorage.setItem(AUTH_STORAGE_KEY, raw); } catch {}
  }
  clearTrustedDevice();
}
function activateTrustedDevice(authSession){
  const userId = authSession?.user?.id;
  if (!userId) return false;
  const until = Date.now() + TRUST_WINDOW_MS;
  try {
    const raw = sessionStorage.getItem(AUTH_STORAGE_KEY) || JSON.stringify(authSession);
    localStorage.setItem(TRUSTED_DEVICE_KEY, JSON.stringify({ v:1, userId, until }));
    localStorage.setItem(AUTH_STORAGE_KEY, raw);
    sessionStorage.removeItem(AUTH_STORAGE_KEY);
    stagedAuthValue = null;
    trustedSessionDeadline = until;
    scheduleTrustedExpiry();
    return true;
  } catch {
    clearTrustedDevice();
    return false;
  }
}
function usingTrustedSession(){
  return !!session && trustedSessionDeadline > Date.now();
}
function syncTrustedDeadlineFromStorage(){
  const trusted = readTrustedDevice();
  if (session && trusted?.userId === session.user?.id) {
    trustedSessionDeadline = trusted.until;
    clearTimeout(idleExpiryTimer); idleExpiryTimer = null;
    scheduleTrustedExpiry();
    return true;
  }
  return false;
}
function scheduleTrustedExpiry(){
  clearTimeout(trustedExpiryTimer);
  if (!trustedSessionDeadline) return;
  const delay = Math.max(0, trustedSessionDeadline - Date.now()) + 50;
  // Browsers clamp very long timers. Re-check at least once per day until due.
  trustedExpiryTimer = setTimeout(() => {
    trustedExpiryTimer = null;
    if (trustedSessionDeadline <= Date.now()) void forceSignOut("trusted-expired");
    else scheduleTrustedExpiry();
  }, Math.min(delay, 24 * 60 * 60 * 1000));
}
const authStorage = {
  getItem(key){
    if (key !== AUTH_STORAGE_KEY) { try { return sessionStorage.getItem(key); } catch { return null; } }
    const trusted = readTrustedDevice();
    if (trusted) { try { return localStorage.getItem(key); } catch {} }
    try { return sessionStorage.getItem(key) || stagedAuthValue; } catch { return stagedAuthValue; }
  },
  setItem(key, value){
    if (key !== AUTH_STORAGE_KEY) { try { sessionStorage.setItem(key, value); } catch {} return; }
    stagedAuthValue = value;
    if (readTrustedDevice()) {
      try { localStorage.setItem(key, value); sessionStorage.removeItem(key); }
      catch { try { sessionStorage.setItem(key, value); } catch {} }
    } else {
      try { sessionStorage.setItem(key, value); } catch {}
      try { localStorage.removeItem(key); } catch {}
    }
  },
  removeItem(key){
    try { sessionStorage.removeItem(key); } catch {}
    if (key === AUTH_STORAGE_KEY) {
      stagedAuthValue = null;
      try { localStorage.removeItem(key); } catch {}
    }
  },
};
const sb = createClient(cfg.SUPABASE_URL, cfg.SUPABASE_ANON_KEY, {
  auth: {
    storage: authStorage,
    storageKey: AUTH_STORAGE_KEY,
    persistSession: true,
    autoRefreshToken: true,
    detectSessionInUrl: true,
  },
});
// Old drafts were once stored persistently; keep purging those without deleting
// a current, explicitly trusted HR session.
(function purgeLegacyDrafts(){
  try {
    for(let i=localStorage.length-1;i>=0;i--){
      const key=localStorage.key(i);
      if(key?.startsWith("psp_manual_drafts_v2:")) localStorage.removeItem(key);
    }
  } catch {}
})();
function touchLastSeen(now = Date.now()){
  if (usingTrustedSession()) return;
  lastActivityWriteAt = now;
  volatileLastSeenAt = now;
  try { localStorage.setItem(LAST_SEEN_KEY, String(now)); }
  catch { try { sessionStorage.setItem(LAST_SEEN_KEY, String(now)); } catch {} }
  scheduleIdleExpiry(now);
}
function scheduleIdleExpiry(lastSeenAt){
  clearTimeout(idleExpiryTimer);
  const elapsed = Math.max(0, Date.now() - lastSeenAt);
  const delay = Math.max(0, IDLE_LIMIT_MS - elapsed) + 50;
  idleExpiryTimer = setTimeout(() => {
    idleExpiryTimer = null;
    void enforceIdleLimit();
  }, delay);
}
function idleTooLong(){
  let raw = "";
  try { raw = localStorage.getItem(LAST_SEEN_KEY) || ""; } catch {}
  if (!raw) { try { raw = sessionStorage.getItem(LAST_SEEN_KEY) || ""; } catch {} }
  const last = Number(raw || volatileLastSeenAt || 0);
  return !Number.isFinite(last) || last <= 0 || (Date.now() - last) > IDLE_LIMIT_MS;
}
async function enforceIdleLimit(){
  if (!session) return false;
  if (idleSignOutPending) return true;
  if (!trustedSessionDeadline) syncTrustedDeadlineFromStorage();
  if (trustedSessionDeadline) {
    if (trustedSessionDeadline > Date.now()) { scheduleTrustedExpiry(); return false; }
    idleSignOutPending = true;
    try { await forceSignOut("trusted-expired"); }
    finally { idleSignOutPending = false; }
    return true;
  }
  if (!idleTooLong()) return false;
  idleSignOutPending = true;
  try {
    await forceSignOut("idle");
    render();
  } finally {
    idleSignOutPending = false;
  }
  return true;
}
function recordUserActivity(event){
  if (!event.isTrusted || !session) return;
  if (!trustedSessionDeadline) syncTrustedDeadlineFromStorage();
  if (trustedSessionDeadline) {
    if (trustedSessionDeadline <= Date.now()) void enforceIdleLimit();
    return;
  }
  if (idleSignOutPending || idleTooLong()) {
    if (event.cancelable) event.preventDefault();
    event.stopImmediatePropagation();
    if (!idleSignOutPending) void enforceIdleLimit();
    return;
  }
  const now = Date.now();
  if (now - lastActivityWriteAt >= ACTIVITY_WRITE_INTERVAL_MS) touchLastSeen(now);
}
async function forceSignOut(reason){
  signedOutReason = reason || "";
  publishCrossTabSignOut();
  stagePersistedSessionForSignOut();
  try { localStorage.removeItem(LAST_SEEN_KEY); } catch {}
  try { sessionStorage.removeItem(LAST_SEEN_KEY); } catch {}
  volatileLastSeenAt = 0;
  lastActivityWriteAt = 0;
  clearTimeout(idleExpiryTimer); idleExpiryTimer = null;
  clearAllManualDrafts();
  resetSessionState();
  activeUserId = null;
  session = null;
  render();
  try { await sb.auth.signOut({ scope:"local" }); }
  catch {}
  finally { clearAllAuthStorage(); }
}

// NOTE (meeting 2026-07-13): harassment/discrimination is deliberately NOT an
// option — HR classifies internally after review. FINAL LIST STILL OPEN — placeholder:
const CATEGORIES = ["Manager conduct","Coworker conduct","Workplace safety","Pay / hours dispute","Policy violation","Customer incident","Other"];
const RELATIONSHIPS = ["Employee","Former employee","Customer","Vendor / partner","Other"];
const REQUEST_TYPES = ["Accommodation — Religious","Accommodation — Medical","Accommodation — Other","Other request"];
const RISKS = ["Low","Medium","High"];
// 8/18 sync call: "Subject" is displayed as "Implicated Person"; Witness is
// split into firsthand / secondhand; "Reporter" added (someone reporting on
// behalf of others). Stored values are kept stable for data continuity —
// legacy rows with plain 'witness' stay valid and display as "Witness".
// NOTE: the new stored values require migration 015 (widened role check).
const PARTY_ROLES = ["subject","victim","witness_firsthand","witness_secondhand","reporter"];
// Neutral wording: stored value stays 'victim' for data continuity,
// but it is ALWAYS displayed as "Impacted team member".
const ROLE_LABEL = { subject:"Implicated Person", victim:"Impacted team member",
  witness:"Witness", witness_firsthand:"Witness — firsthand", witness_secondhand:"Witness — secondhand",
  reporter:"Reporter (on behalf of others)" };
const rlabel = r => ROLE_LABEL[r] || r;
// ER case lifecycle — incidents only; requests keep their own lifecycle.
const INCIDENT_STATES = ["New","Assigned","UnderReview","Investigation","DecisionPending","ActionMonitoring","OnHold"];
const FINDINGS = ["Substantiated","Partially Substantiated","Unsubstantiated","Inconclusive","No Policy Violation","Withdrawn","Referred Elsewhere"];
// Closure categorization (8/28): REQUIRED whenever a case or request is
// closed — replaces deleting bad/test/duplicate cases (8/18: no deletes).
// 'Duplicate' additionally records the other case's ref. Needs migration 017.
const CLOSURE_CATEGORIES = ["Test","Duplicate","Substantiated","Partially Substantiated","Unsubstantiated","Withdrawn"];
const ALLEGATION_TYPES = ["Harassment","Discrimination","Retaliation","Bullying / abusive conduct","Workplace violence / threats",
  "Safety violation","Wage & hour / timekeeping","Attendance / leave","Theft / dishonesty","Confidentiality breach",
  "Fraternization","Substance policy","Code of conduct — other"];
const POLICY_LIST = ["Equal Employment Opportunity","Anti-Harassment Policy","Gossip, Bullying, Abusive Conduct or Communications",
  "Complaint Procedure","Reasonable Accommodations","Fraternization","Meal Period and Rest Break Policy","Attendance",
  "Confidential Information","Workplace safety","Work Schedules","Other (see notes)"];
const CORRECTIVE_TYPES = ["Coaching / counseling","Verbal warning","Written warning","Final warning","Suspension",
  "Termination","Training required","Schedule / transfer change","Policy change","Other"];
const INTERVIEW_STATUS = ["Scheduled","Completed","Canceled"];
// --- accommodation requests (2026-07-23) ---
const ACC_STATUS = ["Approved","Approved with Alternative","Denied","Withdrawn"];
// NOTE: the medical form offers Permanent/Temporary/Unknown; the approved list uses these two.
const ACC_DURATION = ["Temporary","Ongoing"];
// Requests have their own lifecycle. Transitions are deliberately loose — a real
// interactive process loops (waiting on a doctor's note → review → waiting again) —
// and every move is written to the audit log regardless.
const REQ_STATES = ["Assigned","UnderReview","AwaitingInformation","InInteractiveProcess","Monitoring"];
// --- Workers' Comp tracker (source workbook spec, 2026-08-21) ---
// Dropdown values come from the workbook's "Lists" tab, verbatim.
const WC_MARKETS = ["Berkeley","San Francisco","San Diego / Carlsbad","New York City","Seattle","Washington DC","Mamaroneck NY","Armonk NY","Darien CT","Fairfield CT","Collegeville PA","Boston MA"];
const WC_STATES = ["CA","NY","WA","DC","CT","PA","MA"];
const WC_OSHA = ["Yes","No","TBD"];
const WC_CLAIM_TYPES = ["Medical Only","Lost Time / Indemnity","Report Only","Denied"];
const WC_CLAIM_STATUS = ["Open","Investigating","Pending","Litigation","Closed","Denied"];
const WC_WORK_STATUS = ["Full Duty","Modified / Restricted","Off Work","Returned - Full Duty"];
const WC_ASSIGNEES = ["People Team","Claims Lead","Legal"];
// --- Legal & Claims tracker (source workbook spec, 8/18) ---
// Dropdown values are the ones seen in the workbook. All of these are
// SUGGESTIONS, not constraints — the editor keeps off-list stored values
// selectable (opt() pattern) and the DB (migration 018) doesn't check them,
// except risk_level and case_state which are fixed sets.
const LEGAL_STATES = ["Active","Completed"];
const LEGAL_STATUSES = ["Received","Documentation Sent","Negotiating","Litigation"];
const LEGAL_TYPES = ["Lawsuit","Demand Letter","PAGA","Jurisdictional Audit","Administrative Claim"];
const LEGAL_COUNSEL = ["Alexis Law Firm","Fisher Philips","Karlan","Littler","Earthbar Team","NA"];
const LEGAL_EB_POINTS = ["Legal","People Team","Operations"];
const LEGAL_EPLI = ["Yes","No","TBD"];
// Per-intake-type wording. Labels only: the database columns keep their names.
function L(c, key){
  const r = c && c.intake_type === "request";
  return ({ reporter: r?"Requester":"Reporter",
            risk:     r?"Priority / time sensitivity":"Risk level",
            riskCol:  r?"Priority":"Risk",
            handler:  r?"Case owner":"Handler",
            evidence: r?"Supporting Documents":"Evidence",
            guide:    r?"Interactive Process Guide":"Interview guide" })[key];
}
const NEXT = {
  Submitted:["Triage"], Triage:["Assigned","Escalated"], Assigned:["UnderReview"],
  UnderReview:["Action","OnHold"], Action:["Resolved"], Resolved:["Closed","UnderReview"],
  OnHold:["UnderReview"], Escalated:["Assigned"], Closed:["UnderReview"],
};
const SLABEL = { UnderReview:"Under Review", OnHold:"On Hold",
  AwaitingInformation:"Awaiting Information", InInteractiveProcess:"In Interactive Process",
  DecisionPending:"Decision Pending", ActionMonitoring:"Action / Monitoring" };
const stlabel = s => SLABEL[s] || s;

// ---- state ----
let session = null, me = null, isHandler = false, isAdmin = false, signedOutReason = "", trustedDeviceNotice = "";
let dirList = [], dirMap = {}, storeList = [], stateMap = {}, statesList = [];
let view = "home", selected = null, busy = false, errorMsg = "";
let auth = { email:"", sent:false, err:"", remember:false };
let form = blankIncident();
let qform = { location:"", body:"", email:"", rtype:REQUEST_TYPES[0] };
let dashView = "cases";
let receipt = null, statusResult = null, myReports = [], myReportsError = "", myReportsLoading = true, myReportsLoaded = false;
let myReportsPromise = null;
let filters = { q:"", risk:"", cat:"", state:"", handler:"", from:"", to:"", acc:"", dur:"", region:"", district:"" };
// 8/18 call: state changes need a second "save" click before anything is
// recorded — first click arms the move, second click confirms it.
let pendingAdvance = null;   // { id, to } while a state move awaits confirmation
let showFilters = false, showGuide = false, showReassign = false;
let hrTeam = [];
let showManual = false, manual = blankIncident(true);
let wcSelected = null;      // null = list; "new" = create form; else wc_cases.id
let wcFilters = { q:"", status:"", state:"", asg:"" };
let lgSelected = null;      // null = list; "new" = create form; else legal_cases.id
let lgFilters = { q:"", state:"Active", risk:"", status:"", type:"" };   // Active by default (spec)
let closeModal = { open:false, caseId:null, kind:"incident", sub:null, status:"", note:"", cat:"", ref:"" };
let lastShown = [];        // rows currently visible on the cases/requests dashboard (feeds Export CSV)
let caseExport = null;     // everything fetched for the open case detail (feeds Export case .zip)
let lookup = { query:"", picked:null, result:null, err:"" };
let evidence = { list:[], err:"" };
let partySearchResults = [], partySearchSeq = 0, partySearchTimer = null, partySearchError = "";
let partyEditor = { open:false, caseId:null, expectedUpdatedAt:null, parties:[], query:"", role:"subject", busy:false, err:"" };
let evidenceRetry = { caseId:null, files:[] };
let activeUserId = null, sessionEpoch = 0;

function verifiedEmail(){ return (session?.user?.email || "").trim().toLowerCase(); }
function canUseDirectorySearch(){ return !!session; }
function resetSessionState(){
  clearTimeout(idleExpiryTimer); idleExpiryTimer = null;
  clearTimeout(trustedExpiryTimer); trustedExpiryTimer = null;
  trustedSessionDeadline = 0;
  clearAllManualDrafts();
  sessionEpoch += 1;
  clearTimeout(partySearchTimer); partySearchTimer = null; partySearchSeq += 1;
  clearTimeout(draftTimer); draftTimer = null;
  me = null; isHandler = false; isAdmin = false; trustedDeviceNotice = "";
  auth = { email:"", sent:false, err:"", remember:false };
  dirList = []; dirMap = {}; storeList = []; stateMap = {}; statesList = []; hrTeam = [];
  view = "home"; selected = null; busy = false; errorMsg = "";
  form = blankIncident();
  qform = { location:"", body:"", email:"", rtype:REQUEST_TYPES[0] };
  dashView = "cases"; receipt = null; statusResult = null;
  myReports = []; myReportsError = ""; myReportsLoading = true; myReportsLoaded = false; myReportsPromise = null;
  filters = { q:"", risk:"", cat:"", state:"", handler:"", from:"", to:"", acc:"", dur:"", region:"", district:"" };
  pendingAdvance = null; showFilters = false; showGuide = false; showReassign = false;
  showManual = false; manual = blankIncident(true); manualDraftAt = null; draftPending = false; draftSaveFailed = false;
  wcSelected = null; wcFilters = { q:"", status:"", state:"", asg:"" };
  lgSelected = null; lgFilters = { q:"", state:"Active", risk:"", status:"", type:"" };
  closeModal = { open:false, caseId:null, kind:"incident", sub:null, status:"", note:"", cat:"", ref:"" };
  lastShown = []; caseExport = null; caseAllegs = [];
  lookup = { query:"", picked:null, result:null, err:"" };
  evidence = { list:[], err:"" }; evidenceRetry = { caseId:null, files:[] };
  partySearchResults = []; partySearchError = "";
  partyEditor = { open:false, caseId:null, expectedUpdatedAt:null, parties:[], query:"", role:"subject", busy:false, err:"" };
}

function todayStr(){ const d=new Date(); return d.getFullYear()+'-'+String(d.getMonth()+1).padStart(2,'0')+'-'+String(d.getDate()).padStart(2,'0'); }
function blankIncident(isManual = false){
  return { anonymous:false, location:"", usState:"", relationship:"Employee", role:"",
    category:CATEGORIES[0], parties:[], pQuery:"", pType:"employee", pName:"",
    pRoles:["subject"], description:"", email:"", phone:"", files:[], manual:isManual,
    incidentDate: todayStr() };
}
// Location dropdown grouped by state; if a state is chosen, only its stores show.
function locationOptions(selected, chosenState){
  const groups = {};
  for (const s of storeList){
    const st = stateMap[s] || "Other";
    if (chosenState && st !== chosenState) continue;
    (groups[st] = groups[st] || []).push(s);
  }
  let html = `<option value="">— Select a location —</option>`;
  for (const st of Object.keys(groups).sort()){
    html += `<optgroup label="${esc(st)}">` +
      groups[st].map(s=>`<option value="${esc(s)}" ${selected===s?'selected':''}>${esc(s)}</option>`).join("") +
      `</optgroup>`;
  }
  html += `<option value="Other / not store-specific" ${selected==='Other / not store-specific'?'selected':''}>Other / not store-specific</option>`;
  return html;
}

const $ = id => document.getElementById(id);
const esc = s => (s==null?"":String(s)).replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;","\"":"&quot;","'":"&#39;"}[c]));
const nameOf = id => dirMap[id]?.name || id || "—";
const roleOf = id => dirMap[id]?.title || "";
const classToken = s => String(s ?? "").replace(/[^A-Za-z0-9_-]/g, "") || "unknown";
const pill = s => `<span class="pill dot s-${classToken(s)}">${esc(stlabel(s))}</span>`;
const riskPill = r => r ? `<span class="pill r-${classToken(r)}">${esc(r)}</span>` : '<span class="muted">—</span>';
const accPill = s => !s ? '<span class="muted">pending</span>'
  : `<span class="pill a-${s.split(' ')[0]}">${esc(s)}</span>`;
const caseRisk = c => c.risk_level || (c.severity === "High" ? "High" : null);
// Region/District come from the embedded store org map (store_org.js), matched
// on normalized location name; stores not in the map bucket under "Other".
const caseRegion = c => storeOrg(c.location)?.region || "Other";
const caseDistrict = c => storeOrg(c.location)?.district || "Other";
// Under the status pill: why the case closed ("Duplicate → EB-2026-0142").
const closureLine = c => c.closure_category
  ? `<div class="muted" style="font-size:11px;margin-top:2px">${esc(c.closure_category)}${c.closure_ref?' → '+esc(c.closure_ref):''}</div>` : "";
// 8/18: "Days open" on the dashboard alongside the SLA column.
const daysOpen = (c, now) => {
  const end = c.closed_at ? new Date(c.closed_at).getTime() : now;
  const d = Math.max(0, Math.floor((end - new Date(c.created_at).getTime())/86400000));
  return c.closed_at ? `${d}<span class="muted" style="font-size:11px"> (closed)</span>` : String(d);
};
// 8/18: hyperlinks in portal messages render as clickable links (input is
// escaped FIRST, then bare http(s) URLs are wrapped).
const linkify = s => esc(s).replace(/\bhttps?:\/\/[^\s<]+/g,
  u => `<a href="${u}" target="_blank" rel="noopener noreferrer">${u}</a>`);
// Friendly message when a v2 RPC isn't deployed yet
const errText = e => /function|does not exist|not exist|PGRST202|schema cache/i.test(e?.message||"")
  ? "This action needs the v2 backend, which isn't deployed yet." : (e?.message || "Unknown error");

Object.assign(window, { go, sendOtp, verifyOtp, signOut,
  setRememberDevice,
  setF, addParty, rmParty, onPartyInput, pickPartyEmp, pickDirectoryResult, toggleRole, mToggleRole, submitIncident, submitRequest,
  setDashView, addNote, toggleGuide, saveAccommodation, toggleReassign, doReassign, setCloseStatus,
  cancelAdvance,
  addAllegationUI, setFindingUI, removeAllegationUI, addPolicyChip, removePolicyChipFromElement,
  saveInterviewUI, addInterviewUI, deleteInterviewUI, saveActionUI, addActionUI, deleteActionUI,
  toggleTask, evDownload, caseFileDownload,
  openCase, closeCase, doAdvance, sendHandlerMsg, doStatusCheck, sendReporterReply,
  setFilter, applyFilters, toggleFilters, toggleManual, setM, mAddParty, mRmParty, mOnPartyInput, mPickPartyEmp, submitManual, discardManualDraft,
  wcOpen, wcClose, wcSave, wcApplyFilters,
  lgOpen, lgClose, lgSave, lgApplyFilters,
  openCloseModal, cancelCloseModal, setCloseSub, setCloseCat, confirmClose,
  exportCasesCsv, exportCaseZip,
  saveRisk, savePolicies, uploadCaseEvidence,
  togglePartyEditor, setPartyEditRole, onPartyEditInput, pickPartyEditEmployee, removePartyEdit, savePartyEdit,
  onLookupInput, pickLookup, backToLookup, retryMyReports, retryEvidenceUploads });

// ---------------- AUTH / BOOTSTRAP ----------------
async function boot(){
  for (const eventName of USER_ACTIVITY_EVENTS) {
    document.addEventListener(eventName, recordUserActivity, true);
  }
  window.addEventListener("storage", event => {
    if (event.key === CROSS_TAB_SIGNOUT_KEY && event.newValue) {
      void acceptCrossTabSignOut();
      return;
    }
    if (event.key !== TRUSTED_DEVICE_KEY) return;
    const trusted = readTrustedDevice();
    if (session && trusted?.userId === session.user?.id) {
      trustedSessionDeadline = trusted.until;
      clearTimeout(idleExpiryTimer); idleExpiryTimer = null;
      scheduleTrustedExpiry();
    } else if (!trusted) {
      trustedSessionDeadline = 0;
      clearTimeout(trustedExpiryTimer); trustedExpiryTimer = null;
    }
  });
  const { data } = await sb.auth.getSession();
  session = data.session;
  activeUserId = session?.user?.id || null;
  const trusted = readTrustedDevice();
  let trustedSignOutPending = trustedSignOutPendingMemory;
  try { trustedSignOutPending = trustedSignOutPending || sessionStorage.getItem(TRUST_SIGNOUT_PENDING_KEY) === "1"; } catch {}
  if (trustedSignOutPending) {
    if (session) await forceSignOut("trusted-expired");
    else { signedOutReason = "trusted-expired"; clearAllAuthStorage(); }
  } else if (session && trusted && trusted.userId === activeUserId) {
    trustedSessionDeadline = trusted.until;
    scheduleTrustedExpiry();
  } else if (trusted) {
    // Never let one account inherit another account's device trust.
    if (session) await forceSignOut("account-changed");
    else clearTrustedDevice();
  }
  // A default session left open but untouched for 24h requires a fresh code.
  if (session && !trustedSessionDeadline && idleTooLong()) await forceSignOut("idle");
  sb.auth.onAuthStateChange((_e, s) => {
    const nextUserId = s?.user?.id || null;
    if(nextUserId !== activeUserId){
      resetSessionState();
      activeUserId = nextUserId;
      if(nextUserId) touchLastSeen();
    }
    session = s;
    if(s){
      const expected = nextUserId;
      loadContext().then(()=>{ if(session?.user?.id === expected) render(); });
    } else { clearAllAuthStorage(); render(); }
  });
  if (session) { touchLastSeen(); await loadContext(); }
  render();
  // re-check whenever the tab is brought back to the front
  document.addEventListener("visibilitychange", async () => {
    if (document.visibilityState !== "visible") return;
    if (!session || await enforceIdleLimit()) return;
    touchLastSeen();
  });
}
async function loadContext(){
  const epoch = sessionEpoch;
  const userId = session?.user?.id;
  const email = verifiedEmail();
  const [a, h] = await Promise.all([ sb.rpc("app_is_admin"), sb.rpc("app_is_handler") ]);
  if(epoch !== sessionEpoch || session?.user?.id !== userId) return;
  const nextIsAdmin = !!a.data, nextIsHandler = !!h.data;
  let dir = [];
  if (nextIsHandler) {
    const result = await sb.from("directory").select("employee_id,name,email,title,store,manager_id");
    dir = result.data || [];
  }
  const { data: ss } = await sb.from("store_states").select("store,us_state");
  let nextTeam = [];
  if (nextIsHandler) {
    const { data: teamRows } = await sb.from("hr_team").select("employee_id,rank").order("rank");
    nextTeam = teamRows || [];
  }
  if(epoch !== sessionEpoch || session?.user?.id !== userId) return;
  isAdmin = nextIsAdmin; isHandler = nextIsHandler;
  if (trustedSessionDeadline && !nextIsHandler) {
    // Remember-device is an HR convenience, not a persistent reporter login.
    demoteTrustedSession();
    touchLastSeen();
    trustedDeviceNotice = "This account is not an HR handler, so it will stay signed in only for this browser session.";
  }
  dirList = dir;
  dirMap = Object.fromEntries(dirList.map(d => [d.employee_id, d]));
  stateMap = Object.fromEntries((ss||[]).map(r => [r.store, r.us_state]));
  storeList = [...new Set((ss||[]).map(r => r.store).filter(Boolean))].sort();
  statesList = [...new Set(Object.values(stateMap))].sort();
  me = dirList.find(d => (d.email||"").toLowerCase() === email) || { name: session.user.user_metadata?.name || email, title:null, email };
  hrTeam = nextTeam;
  form.email = email; qform.email = email;
  if (view === "dashboard" && !isHandler) view = "home";
}
async function sendOtp(){
  signedOutReason = "";
  const email = ($("otp-email")?.value || "").trim().toLowerCase();
  if(!/^\S+@\S+\.\S+$/.test(email)){ auth.err = "Please enter a valid email address."; render(); return; }
  auth.email = email; auth.err = ""; busy = true; render();
  const { error } = await sb.auth.signInWithOtp({ email, options:{ shouldCreateUser:true } });
  busy = false;
  if(error){ auth.err = error.message; } else { auth.sent = true; }
  render();
}
async function verifyOtp(){
  const token = ($("otp-code")?.value || "").trim();
  if(!token){ return; }
  const rememberRequested = !!auth.remember;
  busy = true; render();
  const { data, error } = await sb.auth.verifyOtp({ email: auth.email, token, type: "email" });
  if(error){ busy = false; auth.err = "That code didn't work — check it or request a new one."; render(); return; }
  if (rememberRequested) {
    const handlerCheck = await sb.rpc("app_is_handler");
    if (handlerCheck.error || !handlerCheck.data) {
      trustedDeviceNotice = "Remember this device is available only to verified HR handlers; this sign-in will end when the browser closes.";
    } else if (!activateTrustedDevice(data?.session || session)) {
      trustedDeviceNotice = "This browser blocked persistent storage, so this sign-in will end when the browser closes.";
    } else {
      trustedDeviceNotice = "This private device is remembered for 30 days. Sign out sooner if anyone else may use it.";
    }
  }
  busy = false;
  auth = { email:"", sent:false, err:"", remember:false };
  render();
}
async function signOut(){
  await forceSignOut("");
}

// ---------------- NAV ----------------
function tabs(){
  const t = [{id:"home",label:"Home"},{id:"status",label:"Check my report status"}];
  if (isHandler) t.push({id:"dashboard",label:"HR Dashboard"},{id:"lookup",label:"Employee Lookup"});
  return t;
}
function go(v){
  if ((v==="dashboard"||v==="lookup") && !isHandler) v="home";
  if (showManual){ syncManualFields(); flushManualDraft(true); }   // nav closes the form — persist the debounce tail first
  view=v; clearSelectedCaseState(); receipt=null; errorMsg=""; showManual=false;
  if(v==="status"){ myReportsError=""; myReportsLoading=true; myReportsLoaded=false; }
  render();
}
function renderNav(){
  $("nav").innerHTML = session ? tabs().map(t=>`<button class="${view===t.id?'active':''}" onclick="go('${t.id}')">${t.label}</button>`).join("") : "";
}
function renderUserBox(){
  const el = $("userbox"); if (!el) return;
  if (!session){ el.innerHTML=""; return; }
  el.style.display="flex"; el.style.alignItems="center"; el.style.gap="12px";
  el.innerHTML = `<span class="ub-name">${esc(me?.name||session.user.email)}<br>
    <span class="ub-title">${esc(me?.title||"")}</span></span>
    <button class="btn sm ghost" onclick="signOut()">Sign out</button>`;
}

// ---------------- LOGIN (email one-time code — the only sign-in method) --------
function renderLogin(){
  const ok = cfg.SUPABASE_URL && !cfg.SUPABASE_URL.includes("YOUR-PROJECT");
  if(!ok) return `<div class="card" style="max-width:520px;margin:40px auto">
    <div class="banner err">Configuration needed: set <b>SUPABASE_URL</b> and <b>SUPABASE_ANON_KEY</b> in <code>config.js</code>. See the README.</div></div>`;
  return `<div class="card" style="max-width:520px;margin:40px auto">
    ${signedOutReason==="idle"?`<div class="banner warn" style="margin-bottom:14px"><b>You were signed out.</b> For security, standard sessions end after 24 hours without use. Sign in again to continue.</div>`:""}
    ${signedOutReason==="trusted-expired"?`<div class="banner warn" style="margin-bottom:14px"><b>Your 30-day sign-in expired.</b> Enter a new code to continue.</div>`:""}
    ${signedOutReason==="account-changed"?`<div class="banner warn" style="margin-bottom:14px"><b>The remembered account did not match this session.</b> Sign in again to continue.</div>`:""}
    <h2 class="section">Sign in to the People Support Portal</h2>
    <p class="muted">Enter your email and we'll send you a one-time code. You don't need an @earthbar.com account — any email works.</p>
    ${!auth.sent ? `
      <label>Email address</label>
      <input id="otp-email" type="text" placeholder="you@example.com" value="${esc(auth.email)}">
      <label class="role-opt" style="margin-top:14px"><input type="checkbox" ${auth.remember?'checked':''} onchange="setRememberDevice(this.checked)"> Remember this private device for 30 days</label>
      <p class="note-sm" style="margin:5px 0 0 23px">For verified HR handlers only. Leave this off on shared or public devices.</p>
      <div style="margin-top:14px"><button class="btn" onclick="sendOtp()" ${busy?'disabled':''}>${busy?'<span class="spin"></span> Sending…':'Email me a sign-in code'}</button></div>`
    : `
      <div class="banner ok">We emailed an 8-digit sign-in code to <b>${esc(auth.email)}</b>. Enter it below. (Check spam if you don't see it.)</div>
      <label>8-digit code</label>
      <input id="otp-code" type="text" placeholder="8-digit code" autocomplete="one-time-code" inputmode="numeric">
      <div style="margin-top:14px;display:flex;gap:8px">
        <button class="btn" onclick="verifyOtp()" ${busy?'disabled':''}>${busy?'<span class="spin"></span> Checking…':'Sign in'}</button>
        <button class="btn ghost" onclick="(function(){window.dispatchEvent(new Event('otp-reset'))})()" id="otp-back">Use a different email</button>
      </div>`}
    ${auth.err?`<div class="banner err">${esc(auth.err)}</div>`:""}
    <div class="divider"></div>
    <p class="note-sm">Reported anonymously before? You can check status any time with your claim code after signing in.</p>
    <p class="note-sm">Standard sign-ins end when you close the browser and after 24 hours without use. HR handlers who opt in above stay signed in on that device for up to 30 days.</p>
  </div>`;
}
function setRememberDevice(on){ auth.remember = !!on; }
window.addEventListener("otp-reset", ()=>{ auth={email:"",sent:false,err:"",remember:false}; render(); });

// ---------------- HOME (question vs incident fork) ----------------
function renderHome(){
  return `${trustedDeviceNotice?`<div class="banner ${usingTrustedSession()?'ok':'info'}" style="max-width:720px;margin:24px auto 0">${esc(trustedDeviceNotice)}</div>`:""}${receipt?`<div style="max-width:720px;margin:24px auto 0">${renderReceipt(receipt)}</div>`:""}
  <div class="card" style="max-width:720px;margin:24px auto">
    <h2 class="section">How can HR help?</h2>
    <p class="muted">Choose one to get started.</p>
    <div class="radio-cards" style="margin-top:14px">
      <div class="radio-card fork" onclick="go('request')"><b>I have a request</b>
        <span class="muted">Accommodations (religious, medical) and other formal requests. For general questions, contact People Support directly.</span></div>
      <div class="radio-card fork" onclick="go('incident')"><b>I want to report an incident</b>
        <span class="muted">Something happened that HR should look into. You can report anonymously.</span></div>
    </div>
  </div>`;
}

// ---------------- REQUEST ----------------
function renderRequest(){
  return `<div class="card" style="max-width:720px;margin:0 auto">
    <button class="back" onclick="go('home')">← Back</button>
    <h2 class="section">Make a request to HR</h2>
    <label>What type of request is it?</label>
    <select onchange="qformType(this.value)">${REQUEST_TYPES.map(t=>`<option ${qform.rtype===t?'selected':''}>${t}</option>`).join("")}</select>
    <label>Location (optional)</label>
    <select onchange="qformLoc(this.value)">${["",...storeList].map(s=>`<option value="${esc(s)}" ${qform.location===s?'selected':''}>${s||'— Not store-specific —'}</option>`).join("")}</select>
    <label>Your request</label>
    <textarea id="qbody" placeholder="Describe what you're requesting.">${esc(qform.body)}</textarea>
    <label>Verified sign-in email</label>
    <input id="qemail" type="email" value="${esc(verifiedEmail())}" readonly>
    ${errorMsg?`<div class="banner err">${esc(errorMsg)}</div>`:""}
    <div style="margin-top:18px"><button class="btn" onclick="submitRequest()" ${busy?'disabled':''}>${busy?'<span class="spin"></span> Sending…':'Send request'}</button></div>
  </div>${receipt?renderReceipt(receipt):""}`;
}
window.qformLoc = v => { qform.location = v; };
window.qformType = v => { qform.rtype = v; };
async function submitRequest(){
  const epoch = sessionEpoch;
  qform.body = $("qbody")?.value || ""; qform.email = verifiedEmail();
  errorMsg = "";
  if(!qform.body.trim()){ errorMsg="Please describe your request."; render(); return; }
  if(!/^\S+@\S+\.\S+$/.test(qform.email)){ errorMsg="Please enter a valid email for the reply."; render(); return; }
  busy=true; render();
  let data, error;
  try {
    ({ data, error } = await sb.rpc("submit_case_v2", {
      p_intake_type:"request", p_category:qform.rtype, p_description:qform.body,
      p_anonymous:false, p_location:qform.location||null, p_relationship:null, p_role:null,
      p_contact_email:qform.email, p_contact_phone:null, p_parties:[], p_manual:false, p_incident_date:null }));
  } catch(e) { error = e; }
  if(epoch !== sessionEpoch) return;
  busy=false;
  if(error){ errorMsg = errText(error); render(); return; }
  receipt = Object.assign({question:true}, data);
  qform = { location:"", body:"", email:(session.user.email||""), rtype:REQUEST_TYPES[0] };
  view = "home";   // land back on the home screen with the confirmation on top
  render(); window.scrollTo({top:0,behavior:"smooth"});
}

// ---------------- INCIDENT INTAKE ----------------
function partyBuilder(f, pre){
  // pre = "" for reporter form, "m" for manual-entry form (separate handlers)
  const P = pre ? {input:"mOnPartyInput",pick:"mPickPartyEmp",add:"mAddParty",rm:"mRmParty",set:"setM",role:"mToggleRole"}
                : {input:"onPartyInput",pick:"pickPartyEmp",add:"addParty",rm:"rmParty",set:"setF",role:"toggleRole"};
  const directoryAllowed = !!pre || canUseDirectorySearch();
  const results = f.pType==="employee" && directoryAllowed && f.pQuery.trim().length >= (isHandler ? 2 : 4)
    ? (isHandler ? dirList.filter(d =>
        (d.name||"").toLowerCase().includes(f.pQuery.toLowerCase()) ||
        (d.title||"").toLowerCase().includes(f.pQuery.toLowerCase())).slice(0,8)
      : partySearchResults)
    : [];
  return `
    <label>Who was involved?</label>
    <div class="row" style="align-items:flex-end">
      <div class="col" style="min-width:130px"><span class="mini-l">They are a…</span>
        <select onchange="${P.set}('pType',this.value)"><option value="employee" ${f.pType==='employee'?'selected':''}>Earthbar employee</option><option value="customer" ${f.pType==='customer'?'selected':''}>Customer</option></select></div>
      <div class="col" style="min-width:190px"><span class="mini-l">Their role(s) in this <span style="text-transform:none;letter-spacing:0;font-weight:400">— pick all that apply</span></span>
        <div class="role-multi">${PARTY_ROLES.map(r=>`<label class="role-opt"><input type="checkbox" ${f.pRoles.includes(r)?'checked':''} onchange="${P.role}('${r}',this.checked)"> ${rlabel(r)}</label>`).join("")}</div></div>
      <div class="col" style="min-width:220px">
        ${f.pType==="employee" && directoryAllowed
          ? `<span class="mini-l">Find the employee</span><input id="${pre}psearch" type="text" placeholder="${isHandler?'Search a name or title…':'Enter at least 4 characters…'}" value="${esc(f.pQuery)}" oninput="${P.input}(this.value)">`
          : `<span class="mini-l">${f.pType==="employee"?'Employee name / description':'Customer name / description'}</span><input id="${pre}pname" type="text" placeholder="${f.pType==="employee"?'Enter the person’s name or identifying description':'e.g. customer, tall, red jacket'}" value="${esc(f.pName)}" oninput="${P.set}('pName',this.value,true)">
             <div style="margin-top:6px"><button class="btn sm sec" onclick="${P.add}()">Add ${f.pType==="employee"?'person':'customer'}</button></div>`}
      </div>
    </div>
    ${!pre && partySearchError ? `<div class="banner err" style="margin-top:8px">${esc(partySearchError)}</div>` : ""}
    ${results.map(d=>`<div class="subj-result" data-employee-id="${esc(d.employee_id)}" data-context="${pre?'manual':'reporter'}" onclick="pickDirectoryResult(this)">${esc(d.name)} — <span class="muted">${esc(d.title||'')}${d.store?' · '+esc(d.store):''}</span></div>`).join("")}
    <div style="margin-top:8px">${f.parties.map((p,i)=>`<span class="chip" style="margin-right:6px">${p.type==='employee'?esc(nameOf(p.id)):esc(p.name)+' (customer)'} · <i>${esc(rlabel(p.role_in_case))}</i> <a onclick="${P.rm}(${i})" style="cursor:pointer;color:var(--red);font-weight:700">×</a></span>`).join("") || '<span class="muted">No one added yet.</span>'}</div>`;
}
function renderIncident(){
  return `<div class="card">
    <button class="back" onclick="go('home')">← Back</button>
    <h2 class="section">Report an incident</h2>
    <p class="muted">Only the assigned HR handler can see this — never anyone the report is about.</p>

    <label>Which state is this about?</label>
    <select onchange="setF('usState',this.value);setF('location','')">${["",...statesList].map(s=>`<option value="${esc(s)}" ${form.usState===s?'selected':''}>${s||'— Select a state —'}</option>`).join("")}</select>
    <label>Which location is this about?</label>
    <select onchange="setF('location',this.value)">${locationOptions(form.location, form.usState)}</select>

    <label>When did this happen?</label>
    <input type="date" max="${todayStr()}" value="${esc(form.incidentDate)}" onchange="setF('incidentDate',this.value||todayStr(),true)">

    <label>How do you want to submit?</label>
    <div class="radio-cards">
      <div class="radio-card ${!form.anonymous?'sel':''}" onclick="setF('anonymous',false)"><b>With my name</b><span class="muted">HR can follow up with you directly.</span></div>
      <div class="radio-card ${form.anonymous?'sel':''}" onclick="setF('anonymous',true)"><b>Anonymously</b><span class="muted">HR never sees who you are. You still get email updates, and a claim code for two-way messaging.</span></div>
    </div>
    ${form.anonymous?`<div class="banner ok" style="margin-top:10px">Your name is hidden from HR. Your email is stored securely <b>only</b> so the system can send you updates — the HR team cannot see it.</div>`:""}

    <label>What is your relationship to Earthbar?</label>
    <select onchange="setF('relationship',this.value)">${RELATIONSHIPS.map(r=>`<option ${form.relationship===r?'selected':''}>${r}</option>`).join("")}</select>
    ${form.relationship==="Employee"?`
      <label>Your current role at Earthbar</label>
      <input id="f-role" type="text" placeholder="e.g. Shift lead, EB Brentwood" value="${esc(form.role)}" oninput="setF('role',this.value,true)">`:""}

    <label>Category</label>
    <select onchange="setF('category',this.value)">${CATEGORIES.map(c=>`<option ${form.category===c?'selected':''}>${c}</option>`).join("")}</select>
    <p class="note-sm">Pick the closest fit — HR reviews and classifies every report after it's submitted.</p>

    ${partyBuilder(form,"")}

    <label>What happened?</label>
    <textarea id="f-desc" placeholder="Describe the situation.${form.anonymous?' If anonymous, avoid details that would reveal who you are.':''}" oninput="setF('description',this.value,true)">${esc(form.description)}</textarea>

    <label>Relevant documents <span class="muted" style="font-weight:400">(optional)</span></label>
    <p class="note-sm" style="margin:0 0 6px">If you have any relevant documents for this case, please submit them — photos, screenshots, PDFs.</p>
    <input id="f-files" type="file" multiple>

    <label>Verified sign-in email <span class="muted" style="font-weight:400">(for your case confirmation and updates)</span></label>
    <input id="f-email" type="email" value="${esc(verifiedEmail())}" readonly>
    <p class="note-sm">Nobody sees this address — it goes only to the automated inbox that sends your confirmation and case updates.</p>
    <label>Your phone <span class="muted" style="font-weight:400">(optional)</span></label>
    <input id="f-phone" type="text" value="${esc(form.phone)}" oninput="setF('phone',this.value,true)">

    ${errorMsg?`<div class="banner err">${esc(errorMsg)}</div>`:""}
    <div style="margin-top:18px"><button class="btn" onclick="submitIncident()" ${busy?'disabled':''}>${busy?'<span class="spin"></span> Submitting…':'Submit report'}</button></div>
  </div>${receipt?renderReceipt(receipt):""}`;
}
function setF(k,v,silent){ form[k]=v; if(!silent) render(); }
function onPartyInput(v){
  form.pQuery=v; partySearchResults=[]; partySearchError=""; render();
  let el=$("psearch"); if(el){el.focus();el.setSelectionRange(v.length,v.length);}
  const query = v.trim();
  clearTimeout(partySearchTimer);
  const seq = ++partySearchSeq;
  if(isHandler || !canUseDirectorySearch() || query.length < 4) return;
  partySearchTimer=setTimeout(async()=>{
    const { data, error } = await sb.rpc("directory_search", { p_query: query });
    if(seq !== partySearchSeq || form.pQuery.trim() !== query) return;
    partySearchResults = error ? [] : (data || []);
    partySearchError = error ? "Employee search is temporarily unavailable. Please try again." : "";
    for(const d of partySearchResults) dirMap[d.employee_id] = d;
    render(); el=$("psearch"); if(el){el.focus();el.setSelectionRange(v.length,v.length);}
  },300);
}
// Multi-select roles (8/18): one case_parties row per person+role. Selecting
// several roles is optional — e.g. a reporter can also be flagged as a witness.
function toggleRole(r,on){ const s=new Set(form.pRoles); if(on)s.add(r);else s.delete(r); form.pRoles=[...s]; render(); }
function rolesOrWarn(f){
  if(!f.pRoles.length){ alert("Select at least one role for this person (only one is required)."); return null; }
  return f.pRoles;
}
function pickPartyEmp(id){
  const selectedEmployee = partySearchResults.find(d=>d.employee_id===id);
  if(selectedEmployee) dirMap[id] = selectedEmployee;
  const roles = rolesOrWarn(form); if(!roles) return;
  for(const r of roles) if(!form.parties.some(p=>p.id===id&&p.role_in_case===r)) form.parties.push({type:"employee",id,role_in_case:r});
  form.pQuery=""; partySearchResults=[]; render();
}
function pickDirectoryResult(el){
  const id = el?.dataset?.employeeId || "";
  if(!id) return;
  if(el.dataset.context === "lookup") pickLookup(id);
  else if(el.dataset.context === "manual") mPickPartyEmp(id);
  else pickPartyEmp(id);
}
function addParty(){
  const n=($("pname")?.value||form.pName||"").trim(); if(!n)return;
  const roles = rolesOrWarn(form); if(!roles) return;
  for(const r of roles) if(!form.parties.some(p=>p.type==="customer"&&p.name===n&&p.role_in_case===r)) form.parties.push({type:"customer",name:n,role_in_case:r});
  form.pName=""; render();
}
function rmParty(i){ form.parties.splice(i,1); render(); }

async function submitIncident(){
  const epoch = sessionEpoch;
  form.description = $("f-desc")?.value ?? form.description ?? "";
  form.email = verifiedEmail(); form.phone = (($("f-phone")?.value ?? form.phone)||"").trim();
  form.role = form.relationship==="Employee" ? ($("f-role")?.value||form.role||"") : "";
  const files = Array.from($("f-files")?.files || []);
  errorMsg="";
  if(!form.location){ errorMsg="Please choose a location."; render(); return; }
  if(!form.description.trim()){ errorMsg="Please describe what happened."; render(); return; }
  if(!/^\S+@\S+\.\S+$/.test(form.email)){ errorMsg="An email is required so we can confirm your report and send updates (it's hidden from HR if you're anonymous)."; render(); return; }
  busy=true; render();
  let data, error;
  try {
    ({ data, error } = await sb.rpc("submit_case_v2", {
      p_intake_type:"incident", p_category:form.category, p_description:form.description,
      p_anonymous:form.anonymous, p_location:form.location, p_relationship:form.relationship,
      p_role:form.role||null, p_contact_email:form.email, p_contact_phone:form.phone||null,
      p_parties:form.parties, p_manual:false, p_incident_date:form.incidentDate, p_us_state:form.usState||null }));
  } catch(e) { error = e; }
  if(epoch !== sessionEpoch) return;
  if(error){ busy=false; errorMsg = errText(error); render(); return; }
  // upload evidence after the case exists
  let upNote = "";
  evidenceRetry = { caseId:data?.case_id || null, files:[] };
  if(files.length && data?.case_id){
    const fails = [];
    for(const f of files){
      if(!(await uploadEvidenceFile(data.case_id, f))){ fails.push(f.name); evidenceRetry.files.push(f); }
      if(epoch !== sessionEpoch) return;
    }
    upNote = fails.length ? `⚠️ ${fails.length} of ${files.length} file(s) failed to upload. Retry them below before leaving this page.`
                          : `${files.length} file(s) attached.`;
  }
  busy=false;
  receipt = Object.assign({upNote}, data);
  form = blankIncident(); form.email = verifiedEmail();
  view = "home";   // land back on the home screen with the confirmation on top
  render(); window.scrollTo({top:0,behavior:"smooth"});
}
function renderReceipt(r){
  if(r.question) return `<div class="card"><div class="banner ok"><b>Sent to HR.</b> Reference <span class="ref">${esc(r.ref)}</span> — you'll get a reply at the email you provided.</div></div>`;
  return `<div class="card">
    <div class="banner ok"><b>Report received.</b> Reference <span class="ref">${esc(r.ref)}</span> — a confirmation email is on its way.</div>
    ${r.upNote?`<p class="muted">${esc(r.upNote)}</p>`:""}
    ${evidenceRetry.caseId===r.case_id && evidenceRetry.files.length
      ? `<button class="btn sm sec" onclick="retryEvidenceUploads()" ${busy?'disabled':''}>${busy?'Retrying…':`Retry ${evidenceRetry.files.length} attachment(s)`}</button>`
      : ""}
    ${r.anonymous ? `<p class="muted">Save this claim code — it's how you check status and message HR without revealing who you are. Email updates will still reach you automatically.</p>
      <div class="codebox">${esc(r.claim_code)}</div>
      <p class="note-sm">Shown once. Check it any time under “Check my report status”.</p>`
      : `<p class="muted">You submitted with your name. The assigned handler can follow up with you directly.</p>`}
    <div class="divider"></div>
    <div class="kv"><span class="k">Routed to</span><b>${esc(r.handler)}</b>${r.external?' <span class="warnbadge" style="margin-left:8px">EXTERNAL</span>':''}</div>
    <div class="kv"><span class="k">Why</span><span>${r.route_reason==='default'?'Default handler — no conflict of interest.':r.route_reason==='conflict_reroute'?'Rerouted — the usual handler was connected to this case.':'All internal HR handlers were conflicted → external advisor.'}</span></div>
  </div>`;
}

// ---------------- DASHBOARD ----------------
function setFilter(k,v){ filters[k]=v; }
function applyFilters(){ filters.q = $("flt-q")?.value ?? filters.q; filters.from = $("flt-from")?.value ?? filters.from; filters.to = $("flt-to")?.value ?? filters.to; render(); }
// ^ filters.q must be captured HERE: render() paints "Loading…" (wiping #flt-q)
//   before renderDashboardInto reads it, so reading at render-time gets nothing.
function toggleFilters(){ showFilters=!showFilters; render(); }
function setDashView(v){ if (showManual){ syncManualFields(); flushManualDraft(true); } dashView=v; showManual=false; wcSelected=null; wcFilters={ q:"", status:"", state:"", asg:"" }; lgSelected=null; lgFilters={ q:"", state:"Active", risk:"", status:"", type:"" }; filters={ q:"", risk:"", cat:"", state:"", handler:"", from:"", to:"", acc:"", dur:"", region:"", district:"" }; render(); }
// NOTE: no select("*") on cases — reporter_email/phone are column-locked
// server-side (anonymity guarantee); requesting them is permission-denied.
// closure_category/closure_ref need migration 017 (granted there per 012's rule).
// Module-level: also the raw column list for the CSV export.
const DASH_CASE_COLS = "id,ref,category,description,severity,anonymous,handler_id,external,route_reason,state,created_at,closed_at,incident_date,intake_type,location,us_state,reporter_relationship,reporter_role,reporter_display,risk_level,substantiated,substantiated_note,policies,ai_summary,manual_entry,updated_at,accommodation_status,accommodation_start,accommodation_end,accommodation_duration,closure_category,closure_ref";
async function renderDashboardInto(el){
  const epoch = sessionEpoch;
  if (dashView === "wc") return renderWcInto(el);
  if (dashView === "legal") return renderLegalInto(el);
  const dv = dashView;                       // stale-paint guard (QC 8/31)
  const { data:all, error } = await sb.from("cases")
    .select(DASH_CASE_COLS + ", tasks(status,due_at), case_parties(subject_id,display_name,party_type,role_in_case)")
    .order("created_at",{ascending:false});
  if (epoch !== sessionEpoch || dashView !== dv || !el.isConnected) return;  // view/session changed while loading
  if(error){ el.innerHTML = `<div class="card"><div class="banner err">Could not load cases: ${esc(error.message)}</div></div>`; return; }
  const isReq = dashView === "requests";
  const pool = (all||[]).filter(c => isReq ? c.intake_type === "request" : c.intake_type !== "request");
  const now = Date.now();
  const overdue = c => (c.tasks||[]).some(t => t.status==="open" && t.due_at && new Date(t.due_at).getTime() < now);
  // Show who's implicated without requiring the case detail view.
  const involved = c => (c.case_parties||[]).map(p =>
      p.party_type==="customer" || (!p.subject_id && p.display_name)
        ? `${p.display_name||"Customer"} (customer)` : nameOf(p.subject_id)
    ).filter(Boolean).join(", ");
  const locState = c => c.location ? `${esc(c.location)}${c.us_state?`, ${esc(c.us_state)}`:""}` : (c.us_state?esc(c.us_state):"—");
  const q = ($("flt-q")?.value ?? filters.q).toLowerCase();
  filters.q = q;
  const fromT = filters.from ? new Date(filters.from + "T00:00:00").getTime() : null;
  const toT   = filters.to   ? new Date(filters.to   + "T23:59:59").getTime() : null;
  const shown = pool.filter(c =>
    (isReq || !filters.risk || caseRisk(c)===filters.risk) &&
    (!filters.cat  || c.category===filters.cat) &&
    (!filters.state|| c.state===filters.state) &&
    (!filters.handler || (filters.handler==="__ext" ? c.external : c.handler_id===filters.handler)) &&
    (!isReq || !filters.acc || (filters.acc==="__none" ? !c.accommodation_status : c.accommodation_status===filters.acc)) &&
    (!isReq || !filters.dur || c.accommodation_duration===filters.dur) &&
    (!filters.us || c.us_state===filters.us) &&
    (!filters.region || caseRegion(c)===filters.region) &&
    (!filters.district || caseDistrict(c)===filters.district) &&
    (!fromT || new Date(c.created_at).getTime() >= fromT) &&
    (!toT   || new Date(c.created_at).getTime() <= toT) &&
    (!q || (c.ref||"").toLowerCase().includes(q) || (c.description||"").toLowerCase().includes(q) || (c.location||"").toLowerCase().includes(q) || involved(c).toLowerCase().includes(q)));
  const open = pool.filter(c=>c.state!=="Closed").length;
  const hi = pool.filter(c=>caseRisk(c)==="High").length;
  const od = pool.filter(overdue).length;
  // Filter options come from FIXED lists (plus anything present in the data), so
  // every category/state/team-member is offered even before any case uses it.
  const catOpts = [...new Set([...(isReq?REQUEST_TYPES:CATEGORIES), ...pool.map(c=>c.category)])].filter(Boolean);
  const stateOpts = isReq ? [...REQ_STATES,"Closed"]
                          : [...new Set([...INCIDENT_STATES,"Closed","Reopened", ...pool.map(c=>c.state)])];
  const handlers = hrTeam.map(t=>[t.employee_id, nameOf(t.employee_id)]);
  lastShown = shown;   // what Export CSV downloads — exactly the filtered view
  el.innerHTML = `<div class="card">
      <div style="display:flex;align-items:center;gap:16px;flex-wrap:wrap">
        <h2 class="section" style="margin:0">HR dashboard</h2>
        <div class="dash-toggle">
          <button class="${!isReq?'on':''}" onclick="setDashView('cases')">Cases</button>
          <button class="${isReq?'on':''}" onclick="setDashView('requests')">Requests</button>
          <button onclick="setDashView('wc')">Workers' Comp</button>
          <button onclick="setDashView('legal')">Legal &amp; Claims</button>
        </div>
      </div>
      <div class="row" style="margin:18px 0 4px">
        <div class="stat"><div class="n">${open}</div><div class="l">Open ${isReq?'requests':'cases'}</div></div>
        ${isReq
          ? `<div class="stat"><div class="n">${pool.length}</div><div class="l">Total requests</div></div>`
          : `<div class="stat"><div class="n" style="color:${hi?'var(--danger)':'var(--ok)'}">${hi}</div><div class="l">High risk</div></div>
             <div class="stat"><div class="n" style="color:${od?'var(--warn)':'var(--ok)'}">${od}</div><div class="l">SLA overdue</div></div>`}
      </div>
      <div class="rule"></div>
      <div class="dash-actions">
        <button class="btn sm ghost" onclick="toggleFilters()">${showFilters?'Hide filters':'Filters'}</button>
        <button class="btn sm ghost" onclick="exportCasesCsv()">Export CSV</button>
        ${!isReq?`<button class="btn sm sec" style="margin-left:auto" onclick="toggleManual()">${showManual?'Cancel manual entry':(hasManualDraft()?'Resume draft case':'+ Add case manually')}</button>`:""}
      </div>
      ${showFilters?`<div class="filters">
        <input id="flt-q" type="text" placeholder="Search ref, description, location…" value="${esc(filters.q)}" onkeydown="if(event.key==='Enter')applyFilters()">
        ${!isReq?`<select onchange="setFilter('risk',this.value);applyFilters()"><option value="">Risk: all</option>${RISKS.map(r=>`<option ${filters.risk===r?'selected':''}>${r}</option>`).join("")}</select>`:""}
        <select onchange="setFilter('cat',this.value);applyFilters()"><option value="">${isReq?'Type':'Category'}: all</option>${catOpts.map(c=>`<option ${filters.cat===c?'selected':''}>${esc(c)}</option>`).join("")}</select>
        <select onchange="setFilter('state',this.value);applyFilters()"><option value="">${isReq?'State':'Status'}: all</option>${stateOpts.map(s=>`<option value="${s}" ${filters.state===s?'selected':''}>${stlabel(s)}</option>`).join("")}</select>
        ${isReq?`<select onchange="setFilter('acc',this.value);applyFilters()"><option value="">Outcome: all</option>${ACC_STATUS.map(s=>`<option ${filters.acc===s?'selected':''}>${s}</option>`).join("")}<option value="__none" ${filters.acc==='__none'?'selected':''}>Not yet decided</option></select>
        <select onchange="setFilter('dur',this.value);applyFilters()"><option value="">Duration: all</option>${ACC_DURATION.map(d=>`<option ${filters.dur===d?'selected':''}>${d}</option>`).join("")}</select>`:""}
        <select onchange="setFilter('handler',this.value);applyFilters()"><option value="">${isReq?'Case owner':'Handler'}: all</option>${handlers.map(([id,n])=>`<option value="${id}" ${filters.handler===id?'selected':''}>${esc(n)}</option>`).join("")}<option value="__ext" ${filters.handler==='__ext'?'selected':''}>External advisor</option></select>
        <select onchange="setFilter('us',this.value);applyFilters()"><option value="">State: all</option>${statesList.map(s=>`<option ${filters.us===s?'selected':''}>${s}</option>`).join("")}</select>
        <select onchange="setFilter('region',this.value);applyFilters()"><option value="">Region: all</option>${[...REGIONS,"Other"].map(r=>`<option ${filters.region===r?'selected':''}>${r}</option>`).join("")}</select>
        <select onchange="setFilter('district',this.value);applyFilters()"><option value="">District: all</option>${[...DISTRICTS,"Other"].map(d=>`<option ${filters.district===d?'selected':''}>${esc(d)}</option>`).join("")}</select>
        <span class="mini-l" style="margin:0">Opened</span>
        <input id="flt-from" type="date" value="${esc(filters.from||'')}" onchange="applyFilters()" style="flex:0 1 150px;width:auto">
        <span class="muted">to</span>
        <input id="flt-to" type="date" value="${esc(filters.to||'')}" onchange="applyFilters()" style="flex:0 1 150px;width:auto">
        <button class="btn sm" onclick="applyFilters()">Apply</button>
      </div>`:""}
    </div>
    <div id="manualbox">${showManual&&!isReq?renderManual():""}</div>
    <div class="card" style="padding:8px 0;overflow-x:auto"><table>
      ${isReq
      ? `<thead><tr><th style="padding-left:20px">Ref</th><th>Request type</th><th>Opened</th><th>Requester</th><th>Case owner</th><th>State</th><th>Outcome</th></tr></thead>
      <tbody>${shown.length ? shown.map(c=>`<tr class="clk" onclick="openCase('${c.id}')">
        <td style="padding-left:20px"><span class="ref">${esc(c.ref)}</span></td>
        <td>${esc(c.category)}</td>
        <td>${fmtD(c.created_at)}</td>
        <td>${esc(c.reporter_display||'—')}</td>
        <td>${c.external?'External advisor <span class="warnbadge">EXT</span>':esc(nameOf(c.handler_id))}</td>
        <td>${pill(c.state)}${closureLine(c)}</td>
        <td>${accPill(c.accommodation_status)}</td>
      </tr>`).join("") : `<tr><td colspan="7" style="padding:20px;text-align:center;color:var(--grey)">No requests match.</td></tr>`}</tbody>`
      : `<thead><tr><th style="padding-left:20px">Ref</th><th>Risk</th><th>Category</th><th>Opened</th><th>Location</th><th>Reporter</th><th>Involved</th><th>Handler</th><th>Status</th><th>Days open</th><th>SLA</th></tr></thead>
      <tbody>${shown.length ? shown.map(c=>`<tr class="clk ${overdue(c)?'overdue':''}" onclick="openCase('${c.id}')">
        <td style="padding-left:20px"><span class="ref">${esc(c.ref)}</span></td>
        <td>${riskPill(caseRisk(c))}</td>
        <td>${esc(c.category)}</td>
        <td>${fmtD(c.created_at)}</td>
        <td>${locState(c)}</td>
        <td>${c.anonymous?'<span class="chip">Anonymous</span>':esc(c.reporter_display||'Named')}</td>
        <td>${esc(involved(c))||'—'}</td>
        <td>${c.external?'External advisor <span class="warnbadge">EXT</span>':esc(nameOf(c.handler_id))}</td>
        <td>${pill(c.state)}${closureLine(c)}</td>
        <td>${daysOpen(c, now)}</td>
        <td>${overdue(c)?'<span class="pill due-over">Overdue</span>':'<span class="pill due-ok">On track</span>'}</td>
      </tr>`).join("") : `<tr><td colspan="11" style="padding:20px;text-align:center;color:var(--grey)">No cases match.</td></tr>`}</tbody>`}
    </table></div>`;
}
// ---------------- WORKERS' COMP TRACKER (source spec, 8/21) -----------------
// Derived values are computed here from source dates so they can't go stale:
// Report Lag = reported - injury; Days Away = (RTW || closed || today) - last
// day worked; Days Open = (closed || today) - reported; follow-up flags when due.
const wcDays = (a, b) => (!a || !b) ? null : Math.max(0, Math.round((new Date(b+"T00:00:00") - new Date(a+"T00:00:00"))/86400000));
// Postgres `date` strings parse as UTC midnight — fmtD would show a day early
// in US timezones, so date-only columns get their own formatter (noon-anchored).
const fmtDateOnly = s => !s ? "—" : new Date(String(s).slice(0,10)+"T12:00:00").toLocaleDateString(undefined,{month:"short",day:"numeric",year:"numeric"});
const WC_DEAD = ["Closed","Denied"];
// Due when next_follow_up <= today (start-of-day compare) and the claim is live.
const wcFollowUpDue = w => w.next_follow_up && !WC_DEAD.includes(w.claim_status)
  && new Date(String(w.next_follow_up).slice(0,10)+"T00:00:00") <= new Date();
const wcPill = s => !s ? '<span class="muted">—</span>'
  : `<span class="pill ${s==="Closed"?"due-ok":(s==="Litigation"||s==="Denied"?"due-over":"dot")}">${esc(s)}</span>`;
// Filters live in module state, NOT read from the DOM at render time — render()
// paints "Loading…" (wiping the inputs) before renderWcInto runs. Same lesson
// as applyFilters/#flt-q above.
function wcApplyFilters(){
  wcFilters.q      = $("wc-q")?.value        ?? wcFilters.q;
  wcFilters.status = $("wc-f-status")?.value ?? wcFilters.status;
  wcFilters.state  = $("wc-f-state")?.value  ?? wcFilters.state;
  wcFilters.asg    = $("wc-f-asg")?.value    ?? wcFilters.asg;
  render();
}
async function renderWcInto(el){
  const epoch = sessionEpoch;
  const dv = dashView;                       // stale-paint guard (QC 8/31)
  const { data:list, error } = await sb.from("wc_cases").select("*").order("ref");
  if (epoch !== sessionEpoch || dashView !== dv || !el.isConnected) return;  // view/session changed while loading
  if (error){
    const msg = /does not exist|schema cache|PGRST/i.test(error.message||"")
      ? "The Workers' Comp backend (migration 016) isn't deployed yet." : error.message;
    el.innerHTML = `<div class="card"><div class="banner err">${esc(msg)}</div></div>`; return;
  }
  const todayS = todayStr();
  const rows = list || [];
  const openN = rows.filter(w => !WC_DEAD.includes(w.claim_status)).length;
  const litN = rows.filter(w => w.claim_status === "Litigation" || w.legal_escalation === "Yes").length;
  const fuN = rows.filter(wcFollowUpDue).length;
  const oshaN = rows.filter(w => w.osha_recordable === "Yes").length;
  const incurred = rows.reduce((s,w)=>s+(Number(w.total_incurred)||0),0);
  const q = wcFilters.q.toLowerCase();
  const shown = rows.filter(w =>
    (!wcFilters.status || w.claim_status === wcFilters.status) &&
    (!wcFilters.asg || w.assigned_to === wcFilters.asg) &&
    (!wcFilters.state || w.us_state === wcFilters.state) &&
    (!q || [w.ref, w.employee_name, w.claim_number, w.injury_description, w.location]
        .some(v => (v||"").toLowerCase().includes(q))));
  // A stale selection (row no longer present) must not render as a "new" form —
  // saving it would target the missing id. Drop back to the list instead.
  if (wcSelected && wcSelected !== "new" && !rows.some(w => w.id === wcSelected)) wcSelected = null;
  const sel = wcSelected && wcSelected !== "new" ? rows.find(w => w.id === wcSelected) : null;
  el.innerHTML = `<div class="card">
      <div style="display:flex;align-items:center;gap:16px;flex-wrap:wrap">
        <h2 class="section" style="margin:0">HR dashboard</h2>
        <div class="dash-toggle">
          <button onclick="setDashView('cases')">Cases</button>
          <button onclick="setDashView('requests')">Requests</button>
          <button class="on" onclick="setDashView('wc')">Workers' Comp</button>
          <button onclick="setDashView('legal')">Legal &amp; Claims</button>
        </div>
      </div>
      <div class="row" style="margin:18px 0 4px">
        <div class="stat"><div class="n">${openN}</div><div class="l">Open claims</div></div>
        <div class="stat"><div class="n" style="color:${litN?'var(--danger)':'var(--ok)'}">${litN}</div><div class="l">Legal / litigation</div></div>
        <div class="stat"><div class="n" style="color:${fuN?'var(--warn)':'var(--ok)'}">${fuN}</div><div class="l">Follow-ups due</div></div>
        <div class="stat"><div class="n">${oshaN}</div><div class="l">OSHA recordable</div></div>
        <div class="stat"><div class="n">$${incurred.toLocaleString()}</div><div class="l">Total incurred</div></div>
      </div>
      <div class="rule"></div>
      <div class="dash-actions" style="gap:8px;flex-wrap:wrap">
        <input id="wc-q" type="text" placeholder="Search ref, employee, claim #…" value="${esc(wcFilters.q)}" onkeydown="if(event.key==='Enter')wcApplyFilters()" style="flex:1 1 220px">
        <select id="wc-f-status" onchange="wcApplyFilters()"><option value="">Status: all</option>${WC_CLAIM_STATUS.map(s=>`<option ${wcFilters.status===s?'selected':''}>${s}</option>`).join("")}</select>
        <select id="wc-f-state" onchange="wcApplyFilters()"><option value="">State: all</option>${WC_STATES.map(s=>`<option ${wcFilters.state===s?'selected':''}>${s}</option>`).join("")}</select>
        <select id="wc-f-asg" onchange="wcApplyFilters()"><option value="">Assigned: all</option>${WC_ASSIGNEES.map(s=>`<option ${wcFilters.asg===s?'selected':''}>${s}</option>`).join("")}</select>
        <button class="btn sm sec" style="margin-left:auto" onclick="wcOpen('new')">+ New claim</button>
      </div>
    </div>
    ${wcSelected ? wcEditor(sel) : ""}
    <div class="card" style="padding:8px 0;overflow-x:auto"><table>
      <thead><tr><th style="padding-left:20px">Case ID</th><th>Employee</th><th>Location</th><th>Injury / Reported</th><th>Body part</th><th>Claim type</th><th>Status</th><th>Work status</th><th>Incurred</th><th>Assigned</th><th>Next follow-up</th><th>Days open</th></tr></thead>
      <tbody>${shown.length ? shown.map(w=>{
        const dOpen = wcDays(w.date_reported || (w.created_at||"").slice(0,10), w.date_closed || todayS);
        return `<tr class="clk ${wcFollowUpDue(w)?'overdue':''}" onclick="wcOpen('${esc(w.id)}')">
        <td style="padding-left:20px"><span class="ref">${esc(w.ref)}</span>${w.legal_escalation==='Yes'?' <span class="warnbadge">LEGAL</span>':''}</td>
        <td>${esc(w.employee_name)}</td>
        <td>${esc(w.location||'—')}${w.us_state?`, ${esc(w.us_state)}`:''}</td>
        <td>${w.date_of_injury?fmtDateOnly(w.date_of_injury):'—'}${w.date_reported?` <span class="muted" style="font-size:11px">rpt ${fmtDateOnly(w.date_reported)}</span>`:''}</td>
        <td>${esc(w.body_part||'—')}</td>
        <td>${esc(w.claim_type||'—')}</td>
        <td>${wcPill(w.claim_status)}</td>
        <td>${esc(w.work_status||'—')}</td>
        <td>${w.total_incurred ? '$'+Number(w.total_incurred).toLocaleString() : '$0'}</td>
        <td>${esc(w.assigned_to||'—')}</td>
        <td>${w.next_follow_up ? (wcFollowUpDue(w)?`<span class="pill due-over">${fmtDateOnly(w.next_follow_up)}</span>`:fmtDateOnly(w.next_follow_up)) : '—'}</td>
        <td>${dOpen==null?'—':dOpen}</td>
      </tr>`;}).join("") : `<tr><td colspan="12" style="padding:20px;text-align:center;color:var(--grey)">No claims match.</td></tr>`}</tbody>
    </table></div>`;
}
function wcEditor(w){
  const v = k => esc(w ? (w[k] ?? "") : "");
  const d = k => esc(w && w[k] ? String(w[k]).slice(0,10) : "");
  // A stored value missing from the fixed list (list edits, imports) must stay
  // selectable — otherwise the next save silently blanks the field.
  const opt = (list, cur, blank=true) => {
    const l = (cur && !list.includes(cur)) ? [...list, cur] : list;
    return (blank?`<option value=""></option>`:"") +
      l.map(o=>`<option value="${esc(o)}" ${cur===o?'selected':''}>${esc(o)}</option>`).join("");
  };
  const lag = w ? wcDays(w.date_of_injury, w.date_reported) : null;
  const away = w && w.last_day_worked ? wcDays(w.last_day_worked, w.rtw_date || w.date_closed || todayStr()) : null;
  return `<div class="card">
    <div style="display:flex;align-items:center;gap:10px">
      <b style="font-size:16px">${w ? `${esc(w.ref)} — edit claim` : "New workers' comp claim"}</b>
      ${lag!=null?`<span class="chip">report lag ${lag}d</span>`:""}
      ${away!=null?`<span class="chip">days away ${away}</span>`:""}
      <button class="btn sm ghost" style="margin-left:auto" onclick="wcClose()">Cancel</button>
      <button class="btn sm" onclick="wcSave()">${w?"Save changes":"Create claim"}</button>
    </div>
    <div class="rule"></div>
    <div class="mini-l">Identification</div>
    <div class="grid2">
      <div><label>Employee name *</label><input id="wc-employee_name" type="text" value="${v('employee_name')}"></div>
      <div><label>Employee ID</label><input id="wc-employee_id" type="text" value="${v('employee_id')}"></div>
      <div><label>Job title</label><input id="wc-job_title" type="text" value="${v('job_title')}"></div>
      <div><label>Claim # (carrier)</label><input id="wc-claim_number" type="text" value="${v('claim_number')}"></div>
      <div><label>Location (market)</label><select id="wc-location">${opt(WC_MARKETS, w?w.location:"")}</select></div>
      <div><label>State</label><select id="wc-us_state">${opt(WC_STATES, w?w.us_state:"")}</select></div>
    </div>
    <div class="mini-l" style="margin-top:12px">Incident</div>
    <div class="grid2">
      <div><label>Date of injury</label><input id="wc-date_of_injury" type="date" value="${d('date_of_injury')}"></div>
      <div><label>Date reported</label><input id="wc-date_reported" type="date" value="${d('date_reported')}"></div>
      <div><label>Body part</label><input id="wc-body_part" type="text" value="${v('body_part')}"></div>
      <div><label>Cause / nature</label><input id="wc-cause_nature" type="text" value="${v('cause_nature')}"></div>
      <div><label>OSHA recordable</label><select id="wc-osha_recordable">${opt(WC_OSHA, w?w.osha_recordable:"")}</select></div>
    </div>
    <div><label>Injury description</label><textarea id="wc-injury_description" rows="2">${v('injury_description')}</textarea></div>
    <div class="mini-l" style="margin-top:12px">Claim</div>
    <div class="grid2">
      <div><label>Claim type</label><select id="wc-claim_type">${opt(WC_CLAIM_TYPES, w?w.claim_type:"")}</select></div>
      <div><label>Claim status</label><select id="wc-claim_status">${opt(WC_CLAIM_STATUS, w?w.claim_status:"Open", false)}</select></div>
      <div><label>Insurance carrier</label><input id="wc-insurance_carrier" type="text" value="${v('insurance_carrier')}"></div>
      <div><label>Adjuster / contact</label><input id="wc-adjuster_contact" type="text" value="${v('adjuster_contact')}"></div>
    </div>
    <div class="mini-l" style="margin-top:12px">Work status / return-to-work</div>
    <div class="grid2">
      <div><label>Work status</label><select id="wc-work_status">${opt(WC_WORK_STATUS, w?w.work_status:"")}</select></div>
      <div><label>Last day worked</label><input id="wc-last_day_worked" type="date" value="${d('last_day_worked')}"></div>
      <div><label>RTW date</label><input id="wc-rtw_date" type="date" value="${d('rtw_date')}"></div>
      <div><label>Restrictions</label><input id="wc-restrictions" type="text" value="${v('restrictions')}"></div>
    </div>
    <div class="mini-l" style="margin-top:12px">Financial &amp; admin</div>
    <div class="grid2">
      <div><label>Total incurred ($)</label><input id="wc-total_incurred" type="number" step="0.01" value="${v('total_incurred')||'0'}"></div>
      <div><label>Assigned to</label><select id="wc-assigned_to">${opt(WC_ASSIGNEES, w?w.assigned_to:"")}</select></div>
      <div><label>Legal escalation</label><select id="wc-legal_escalation">${opt(["No","Yes"], w?w.legal_escalation:"No", false)}</select></div>
      <div><label>Next follow-up</label><input id="wc-next_follow_up" type="date" value="${d('next_follow_up')}"></div>
      <div><label>Date closed</label><input id="wc-date_closed" type="date" value="${d('date_closed')}"></div>
    </div>
    <div><label>Case notes</label><textarea id="wc-case_notes" rows="3">${v('case_notes')}</textarea></div>
    <div id="wc-err"></div>
  </div>`;
}
function wcOpen(id){ wcSelected = id; render(); window.scrollTo({top:0,behavior:"smooth"}); }
function wcClose(){ wcSelected = null; render(); }
async function wcSave(){
  const F = ["employee_name","employee_id","job_title","claim_number","location","us_state",
    "date_of_injury","date_reported","body_part","cause_nature","osha_recordable","injury_description",
    "claim_type","claim_status","insurance_carrier","adjuster_contact",
    "work_status","last_day_worked","rtw_date","restrictions",
    "total_incurred","assigned_to","legal_escalation","next_follow_up","date_closed","case_notes"];
  const p = {};
  for (const f of F) p[f] = ($("wc-"+f)?.value ?? "").trim();
  const err = m => { const el=$("wc-err"); el.innerHTML = `<div class="banner err">${esc(m)}</div>`; el.scrollIntoView({behavior:"smooth",block:"center"}); };
  if (!p.employee_name){ err("Employee name is required."); return; }
  const { error } = await sb.rpc("wc_save", { p_id: wcSelected === "new" ? null : wcSelected, p });
  if (error){ err(errText(error)); return; }
  wcSelected = null; render();
}

// ---------- LEGAL & CLAIMS TRACKER (source workbook spec, 8/18) -----------
// Structural sibling of the Workers' Comp tab: legal_cases table + legal_save
// RPC (migration 018), module-state filters, noon-anchored date-only rendering.
// "Overdue" = due_date <= today (start-of-day compare) on an Active case.
const lgDue = r => r.case_state === "Active" && r.due_date
  && new Date(String(r.due_date).slice(0,10)+"T00:00:00") <= new Date();
const lgStatusPill = s => !s ? '<span class="muted">—</span>'
  : `<span class="pill ${s==="Litigation"?"due-over":"dot"}">${esc(s)}</span>`;
// docs_link is UNTRUSTED free text (the workbook mixed URLs and prose, and one
// cell holds two URLs). Only http(s) URLs become links — attribute-escaped, and
// target=_blank always pairs with rel="noopener noreferrer". Anything else
// renders as plain escaped text.
function lgDocsCell(v){
  if (!v) return '<span class="muted">—</span>';
  const urls = String(v).match(/\bhttps?:\/\/[^\s<]+/g);
  if (!urls) return `<span class="muted">${esc(v)}</span>`;
  return urls.map((u,i)=>`<a href="${esc(u)}" target="_blank" rel="noopener noreferrer">Folder${urls.length>1?" "+(i+1):""}</a>`).join(", ");
}
// Filters live in module state, NOT read from the DOM at render time — render()
// paints "Loading…" (wiping the inputs) before renderLegalInto runs. Same
// lesson as applyFilters/#flt-q and wcApplyFilters.
function lgApplyFilters(){
  lgFilters.q      = $("lg-q")?.value        ?? lgFilters.q;
  lgFilters.state  = $("lg-f-state")?.value  ?? lgFilters.state;
  lgFilters.risk   = $("lg-f-risk")?.value   ?? lgFilters.risk;
  lgFilters.status = $("lg-f-status")?.value ?? lgFilters.status;
  lgFilters.type   = $("lg-f-type")?.value   ?? lgFilters.type;
  render();
}
async function renderLegalInto(el){
  const epoch = sessionEpoch;
  const dv = dashView;                       // stale-paint guard (QC 8/31)
  const { data:list, error } = await sb.from("legal_cases").select("*").order("ref");
  if (epoch !== sessionEpoch || dashView !== dv || !el.isConnected) return;  // view/session changed while loading
  if (error){
    const msg = /does not exist|schema cache|PGRST/i.test(error.message||"")
      ? "The Legal & Claims backend (migration 018) isn't deployed yet." : error.message;
    el.innerHTML = `<div class="card"><div class="banner err">${esc(msg)}</div></div>`; return;
  }
  const rows = list || [];
  // Stat tiles are scoped to ACTIVE cases — a completed matter's risk or old
  // "Litigation" status shouldn't inflate the live picture.
  const act = rows.filter(r => r.case_state === "Active");
  const activeN = act.length;
  const hiN = act.filter(r => r.risk_level === "High").length;
  const litN = act.filter(r => r.status === "Litigation").length;
  const dueN = rows.filter(lgDue).length;
  const q = lgFilters.q.toLowerCase();
  const shown = rows.filter(r =>
    (!lgFilters.state  || r.case_state === lgFilters.state) &&
    (!lgFilters.risk   || r.risk_level === lgFilters.risk) &&
    (!lgFilters.status || r.status === lgFilters.status) &&
    (!lgFilters.type   || r.claim_type === lgFilters.type) &&
    (!q || [r.ref, r.complainant, r.opposing_counsel, r.company_counsel, r.eb_point,
            r.synopsis, r.pending_action, r.epli_notes, r.notes]
        .some(v => (v||"").toLowerCase().includes(q))));
  // Off-list stored values (free-ish columns) must still be offered as filter options.
  const statusOpts = [...new Set([...LEGAL_STATUSES, ...rows.map(r=>r.status)])].filter(Boolean);
  const typeOpts   = [...new Set([...LEGAL_TYPES,    ...rows.map(r=>r.claim_type)])].filter(Boolean);
  // A stale selection (row no longer present) must not render as a "new" form —
  // saving it would target the missing id. Drop back to the list instead.
  if (lgSelected && lgSelected !== "new" && !rows.some(r => r.id === lgSelected)) lgSelected = null;
  const sel = lgSelected && lgSelected !== "new" ? rows.find(r => r.id === lgSelected) : null;
  el.innerHTML = `<div class="card">
      <div style="display:flex;align-items:center;gap:16px;flex-wrap:wrap">
        <h2 class="section" style="margin:0">HR dashboard</h2>
        <div class="dash-toggle">
          <button onclick="setDashView('cases')">Cases</button>
          <button onclick="setDashView('requests')">Requests</button>
          <button onclick="setDashView('wc')">Workers' Comp</button>
          <button class="on" onclick="setDashView('legal')">Legal &amp; Claims</button>
        </div>
      </div>
      <div class="row" style="margin:18px 0 4px">
        <div class="stat"><div class="n">${activeN}</div><div class="l">Active cases</div></div>
        <div class="stat"><div class="n" style="color:${hiN?'var(--danger)':'var(--ok)'}">${hiN}</div><div class="l">High risk</div></div>
        <div class="stat"><div class="n" style="color:${litN?'var(--danger)':'var(--ok)'}">${litN}</div><div class="l">In litigation</div></div>
        <div class="stat"><div class="n" style="color:${dueN?'var(--warn)':'var(--ok)'}">${dueN}</div><div class="l">Due follow-ups</div></div>
      </div>
      <div class="rule"></div>
      <div class="dash-actions" style="gap:8px;flex-wrap:wrap">
        <input id="lg-q" type="text" placeholder="Search ref, complainant, counsel, synopsis…" value="${esc(lgFilters.q)}" onkeydown="if(event.key==='Enter')lgApplyFilters()" style="flex:1 1 220px">
        <select id="lg-f-state" onchange="lgApplyFilters()"><option value="">State: all</option>${LEGAL_STATES.map(s=>`<option ${lgFilters.state===s?'selected':''}>${s}</option>`).join("")}</select>
        <select id="lg-f-risk" onchange="lgApplyFilters()"><option value="">Risk: all</option>${RISKS.map(r=>`<option ${lgFilters.risk===r?'selected':''}>${r}</option>`).join("")}</select>
        <select id="lg-f-status" onchange="lgApplyFilters()"><option value="">Status: all</option>${statusOpts.map(s=>`<option ${lgFilters.status===s?'selected':''}>${esc(s)}</option>`).join("")}</select>
        <select id="lg-f-type" onchange="lgApplyFilters()"><option value="">Type: all</option>${typeOpts.map(t=>`<option ${lgFilters.type===t?'selected':''}>${esc(t)}</option>`).join("")}</select>
        <button class="btn sm sec" style="margin-left:auto" onclick="lgOpen('new')">+ New case</button>
      </div>
    </div>
    ${lgSelected ? lgEditor(sel) : ""}
    <div class="card" style="padding:8px 0;overflow-x:auto"><table>
      <thead><tr><th style="padding-left:20px">Case ID</th><th>Risk</th><th>Status</th><th>Complainant</th><th>Type</th><th>Opposing counsel / agency</th><th>Company counsel</th><th>EB point</th><th>Due date</th><th>Docs</th></tr></thead>
      <tbody>${shown.length ? shown.map(r=>`<tr class="clk ${lgDue(r)?'overdue':''}" onclick="lgOpen('${esc(r.id)}')">
        <td style="padding-left:20px"><span class="ref">${esc(r.ref)}</span>${r.case_state==='Completed'?' <span class="chip">Completed</span>':''}</td>
        <td>${riskPill(r.risk_level)}</td>
        <td>${lgStatusPill(r.status)}</td>
        <td>${esc(r.complainant||'—')}</td>
        <td>${esc(r.claim_type||'—')}</td>
        <td>${esc(r.opposing_counsel||'—')}</td>
        <td>${esc(r.company_counsel||'—')}</td>
        <td>${esc(r.eb_point||'—')}</td>
        <td>${r.due_date ? (lgDue(r)?`<span class="pill due-over">${fmtDateOnly(r.due_date)}</span>`:fmtDateOnly(r.due_date)) : (r.due_date_note?`<span class="muted">${esc(r.due_date_note)}</span>`:'—')}</td>
        <td onclick="event.stopPropagation()">${lgDocsCell(r.docs_link)}</td>
      </tr>`).join("") : `<tr><td colspan="10" style="padding:20px;text-align:center;color:var(--grey)">No legal cases match.</td></tr>`}</tbody>
    </table></div>`;
}
function lgEditor(r){
  const v = k => esc(r ? (r[k] ?? "") : "");
  const d = k => esc(r && r[k] ? String(r[k]).slice(0,10) : "");
  // A stored value missing from the fixed list (list edits, imports, free-ish
  // columns) must stay selectable — otherwise the next save silently blanks it.
  const opt = (list, cur, blank=true) => {
    const l = (cur && !list.includes(cur)) ? [...list, cur] : list;
    return (blank?`<option value=""></option>`:"") +
      l.map(o=>`<option value="${esc(o)}" ${cur===o?'selected':''}>${esc(o)}</option>`).join("");
  };
  return `<div class="card">
    <div style="display:flex;align-items:center;gap:10px">
      <b style="font-size:16px">${r ? `${esc(r.ref)} — edit case` : "New legal / claims case"}</b>
      ${r && lgDue(r) ? '<span class="pill due-over">Due follow-up</span>' : ""}
      <button class="btn sm ghost" style="margin-left:auto" onclick="lgClose()">Cancel</button>
      <button class="btn sm" onclick="lgSave()">${r?"Save changes":"Create case"}</button>
    </div>
    <div class="rule"></div>
    <div class="mini-l">Classification</div>
    <div class="grid2">
      <div><label>Case state</label><select id="lg-case_state">${opt(LEGAL_STATES, r?r.case_state:"Active", false)}</select></div>
      <div><label>Risk level</label><select id="lg-risk_level">${opt(RISKS, r?r.risk_level:"")}</select></div>
      <div><label>Status</label><select id="lg-status">${opt(LEGAL_STATUSES, r?r.status:"")}</select></div>
      <div><label>Type</label><select id="lg-claim_type">${opt(LEGAL_TYPES, r?r.claim_type:"")}</select></div>
    </div>
    <div class="mini-l" style="margin-top:12px">Parties</div>
    <div class="grid2">
      <div><label>Complainant</label><input id="lg-complainant" type="text" value="${v('complainant')}"></div>
      <div><label>Opposing counsel or agency</label><input id="lg-opposing_counsel" type="text" value="${v('opposing_counsel')}"></div>
      <div><label>Company legal counsel</label><select id="lg-company_counsel">${opt(LEGAL_COUNSEL, r?r.company_counsel:"")}</select></div>
      <div><label>EB point</label><select id="lg-eb_point">${opt(LEGAL_EB_POINTS, r?r.eb_point:"")}</select></div>
    </div>
    <div><label>Synopsis</label><textarea id="lg-synopsis" rows="4">${v('synopsis')}</textarea></div>
    <div class="mini-l" style="margin-top:12px">EPLI</div>
    <div class="grid2">
      <div><label>Tendered to EPLI?</label><select id="lg-epli_tendered">${opt(LEGAL_EPLI, r?r.epli_tendered:"")}</select></div>
    </div>
    <div><label>EPLI coverage notes</label><textarea id="lg-epli_notes" rows="2">${v('epli_notes')}</textarea></div>
    <div class="mini-l" style="margin-top:12px">Follow-up</div>
    <div><label>Pending action</label><textarea id="lg-pending_action" rows="2">${v('pending_action')}</textarea></div>
    <div class="grid2">
      <div><label>Due date</label><input id="lg-due_date" type="date" value="${d('due_date')}"></div>
      <div><label>Due date note <span class="muted" style="font-weight:400;text-transform:none;letter-spacing:0">(original text when the date was messy)</span></label><input id="lg-due_date_note" type="text" value="${v('due_date_note')}"></div>
    </div>
    <div><label>Related documents folder link</label><input id="lg-docs_link" type="text" value="${v('docs_link')}" placeholder="https://…"></div>
    <div><label>Notes on structure</label><textarea id="lg-notes" rows="2">${v('notes')}</textarea></div>
    <div id="lg-err"></div>
  </div>`;
}
function lgOpen(id){ lgSelected = id; render(); window.scrollTo({top:0,behavior:"smooth"}); }
function lgClose(){ lgSelected = null; render(); }
async function lgSave(){
  const F = ["case_state","risk_level","status","complainant","claim_type",
    "opposing_counsel","company_counsel","eb_point","synopsis",
    "epli_tendered","epli_notes","pending_action",
    "due_date","due_date_note","docs_link","notes"];
  const p = {};
  for (const f of F) p[f] = ($("lg-"+f)?.value ?? "").trim();
  const err = m => { const el=$("lg-err"); el.innerHTML = `<div class="banner err">${esc(m)}</div>`; el.scrollIntoView({behavior:"smooth",block:"center"}); };
  // The workbook has rows identified only by their synopsis (e.g. "Privacy"),
  // so either field is enough — but a fully unlabeled row helps no one.
  if (!p.complainant && !p.synopsis){ err("Enter a complainant or a synopsis."); return; }
  const { error } = await sb.rpc("legal_save", { p_id: lgSelected === "new" ? null : lgSelected, p });
  if (error){ err(errText(error)); return; }
  lgSelected = null; render();
}

// 8/18 call: cases are NEVER deleted from the UI any more — a bad/duplicate
// case should be categorized (e.g. "faulty") instead. The delete_case RPC still
// exists server-side but the dashboard no longer offers it. The "faulty"
// category itself needs a schema decision (see PR notes).
function clearSelectedCaseState(){
  selected=null; pendingAdvance=null; showReassign=false; showGuide=false;
  caseExport=null; caseAllegs=[]; evidence={list:[],err:""};
  partyEditor={ open:false, caseId:null, expectedUpdatedAt:null, parties:[], query:"", role:"subject", busy:false, err:"" };
}
function openCase(id){ clearSelectedCaseState(); selected=id; render(); window.scrollTo({top:0,behavior:"smooth"}); }
function closeCase(){ clearSelectedCaseState(); render(); }

// ---- manual case entry (for reports that reach People Support by email) ---
// Everything typed here is mirrored into `manual` and auto-saved to sessionStorage
// (this tab only), so a re-render or browser refresh can't lose an in-progress
// case. Closing the tab, signing out, successful submit, or "Start fresh" clears it.
// Field changes repaint ONLY the #manualbox card — a full render() on the
// dashboard wipes the DOM with "Loading cases…" and re-fetches every case,
// which is what used to eat unsaved notes on every field change (bug 9/1).
// Store shape: sessionStorage["psp_manual_drafts_v2:<user email>"] = { [tabId]: {at, manual} }.
// Per-USER key: a draft can never restore under a different handler's sign-in
// (shared HR computers), and sign-out wipes every draft on the machine.
// Per-TAB slot: two open tabs each write their own slot, so neither can
// silently clobber the other's work; restore picks the newest slot.
const MANUAL_DRAFT_PREFIX = "psp_manual_drafts_v2:";
const MANUAL_DRAFT_MAX_AGE = 7*24*3600*1000;   // drafts expire after a week
const TAB_ID = (crypto.randomUUID ? crypto.randomUUID() : String(Math.random()).slice(2));
let manualDraftAt = null;    // when the restored draft was last saved (drives the banner)
let draftTimer = null;
let draftPending = false;    // content changed since the last successful write
let draftSaveFailed = false; // last write threw (quota/blocked storage) — surfaced in the form note
function draftKey(){ return MANUAL_DRAFT_PREFIX + ((session?.user?.email)||"anon").toLowerCase(); }
function manualDirty(){
  return !!(manual && ((manual.description||"").trim() || (manual.email||"").trim() || (manual.parties||[]).length));
}
function readDraftStore(){
  try {
    const s = JSON.parse(sessionStorage.getItem(draftKey()) || "{}");
    if (!s || typeof s !== "object") return {};
    let changed = false;
    for (const k of Object.keys(s))
      if (!s[k] || !s[k].manual || Date.now() - (s[k].at||0) >= MANUAL_DRAFT_MAX_AGE) { delete s[k]; changed = true; }
    if (changed) sessionStorage.setItem(draftKey(), JSON.stringify(s));
    return s;
  } catch { return {}; }
}
function writeDraftNow(force){
  if (!session) return;                 // post-sign-out flush must never write (would land under the anon key)
  if (!showManual && !force) return;    // form closed: nothing new to persist (Cancel passes force)
  if (!draftPending) return;            // unchanged since the last successful write
  if (!manualDirty()) return;           // never persist a pristine form (no phantom "restored draft")
  try {
    const s = readDraftStore();
    s[TAB_ID] = { at: Date.now(), manual };
    sessionStorage.setItem(draftKey(), JSON.stringify(s));
    draftPending = false;
    if (draftSaveFailed){ draftSaveFailed = false; paintSaveNote(); }
  } catch { draftSaveFailed = true; paintSaveNote(); }   // quota/blocked storage
}
// Update just the note line under the description box — typing is silent-bound,
// so without this a save failure would stay invisible until the next repaint.
function paintSaveNote(){
  const el = $("m-savenote");
  if (!el) return;
  if (draftSaveFailed){
    el.style.color = "var(--red)"; el.style.fontWeight = "600";
    el.textContent = "Couldn't auto-save this draft in the browser (storage full or blocked) — keep this tab open until you submit.";
  } else {
    el.style.color = ""; el.style.fontWeight = "";
    el.textContent = "Draft auto-saves in this browser as you type and survives a refresh. It's cleared when anyone signs out on this computer.";
  }
}
function saveManualDraft(){ draftPending = true; clearTimeout(draftTimer); draftTimer = setTimeout(writeDraftNow, 300); }
function flushManualDraft(force){ clearTimeout(draftTimer); draftTimer = null; writeDraftNow(force === true); }
// Don't lose the debounce tail: a paste-then-close or F5 within 300ms of the
// last input would otherwise miss the draft entirely.
window.addEventListener("pagehide", ()=>flushManualDraft());
document.addEventListener("visibilitychange", ()=>{ if (document.visibilityState === "hidden") flushManualDraft(); });
function loadManualDraft(){
  const s = readDraftStore();
  let best = null, bestKey = null;
  for (const k of Object.keys(s)) if (!best || (s[k].at||0) > (best.at||0)) { best = s[k]; bestKey = k; }
  if (!best) return null;
  const m = Object.assign(blankIncident(true), best.manual, { manual:true });
  // Normalize restored types — a malformed stored draft must never break rendering.
  if (!Array.isArray(m.parties)) m.parties = [];
  if (!Array.isArray(m.pRoles) || !m.pRoles.length) m.pRoles = ["subject"];
  if (typeof m.pQuery !== "string") m.pQuery = "";
  if (typeof m.description !== "string") m.description = "";
  if (typeof m.email !== "string") m.email = "";
  // A location/category that no longer exists would DISPLAY as blank/first-option
  // while the stale value silently submits — keep display and state in agreement.
  // ("Other / not store-specific" is a legal non-store value the select always offers.)
  if (m.location && m.location !== "Other / not store-specific" && !(storeList||[]).includes(m.location)) m.location = "";
  if (!CATEGORIES.includes(m.category)) m.category = CATEGORIES[0];
  return { at: best.at, key: bestKey, manual: m };
}
function hasManualDraft(){ return loadManualDraft() !== null; }
function clearManualDraft(){
  clearTimeout(draftTimer); draftTimer = null; manualDraftAt = null; draftPending = false;
  try {
    const s = readDraftStore();
    delete s[TAB_ID];
    sessionStorage.setItem(draftKey(), JSON.stringify(s));
  } catch {}
}
// Sign-out wipes every manual draft on this machine (all users' keys) — HR case
// text must not outlive the session on a shared computer.
function clearAllManualDrafts(){
  clearTimeout(draftTimer); draftTimer = null; manualDraftAt = null; draftPending = false;
  try {
    for (let i = sessionStorage.length - 1; i >= 0; i--){
      const k = sessionStorage.key(i);
      if (k && k.startsWith(MANUAL_DRAFT_PREFIX)) sessionStorage.removeItem(k);
    }
  } catch {}
}
function discardManualDraft(){ clearManualDraft(); manual = blankIncident(true); errorMsg = ""; renderManualBox(); }
// Pull DOM-only values into state before any repaint (belt & braces — both
// fields are also bound via oninput below).
function syncManualFields(){
  const d = $("m-desc"), e = $("m-email");
  if (d) manual.description = d.value;
  if (e) manual.email = e.value;
}
function renderManualBox(){
  const el = $("manualbox");
  if (!el) { render(); return; }
  syncManualFields();
  el.innerHTML = showManual ? renderManual() : "";
}
function toggleManual(){
  showManual = !showManual;
  errorMsg = "";   // never carry a stale error banner into a fresh/restored form
  if (showManual) {
    clearTimeout(draftTimer); draftTimer = null;   // a pending save must not overwrite what we're about to restore
    const d = loadManualDraft();
    if (d) {
      manual = d.manual; manualDraftAt = d.at;
      // Claim the restored slot under THIS tab id immediately — an orphaned
      // slot would survive submit and re-offer the already-filed case as a
      // "draft" days later (duplicate-case risk found in QC).
      draftPending = false;
      if (d.key !== TAB_ID) try {
        const s = readDraftStore();
        delete s[d.key];
        s[TAB_ID] = { at: d.at, manual };
        sessionStorage.setItem(draftKey(), JSON.stringify(s));
      } catch {
        // Claim failed (storage broken) — the old slot survives; keep pending so
        // a later successful write still lands, and surface the warning.
        draftPending = true; draftSaveFailed = true;
      }
    }
    else { manual = blankIncident(true); manualDraftAt = null; draftPending = false; }
  } else {
    syncManualFields(); flushManualDraft(true);   // Cancel keeps the draft — saved synchronously (no 300ms race)
  }
  render();   // full render is fine here: the toggle button label lives outside the box
}
function renderManual(){
  return `<div class="card" style="border-color:var(--green)">
    <h2 class="section" style="font-size:16px">Add a case manually <span class="chip">received outside the portal</span></h2>
    ${manualDraftAt?`<div class="banner ok" style="margin:6px 0 10px">Restored your unsaved draft (from ${esc(new Date(manualDraftAt).toLocaleString())}). <a onclick="discardManualDraft()" style="cursor:pointer;font-weight:700;text-decoration:underline">Start fresh instead</a></div>`:""}
    <label>Reporter's email (if known)</label><input id="m-email" type="text" value="${esc(manual.email)}" oninput="setM('email',this.value,true)">
    <label>Location</label>
    <select onchange="setM('location',this.value)">${locationOptions(manual.location, "")}</select>
    <label>Category</label>
    <select onchange="setM('category',this.value)">${CATEGORIES.map(c=>`<option ${manual.category===c?'selected':''}>${c}</option>`).join("")}</select>
    <label>When did it happen? (if known)</label>
    <input type="date" max="${todayStr()}" value="${esc(manual.incidentDate)}" onchange="setM('incidentDate',this.value,true)">
    ${partyBuilder(manual,"m")}
    <label>Description (paste the report as received)</label>
    <textarea id="m-desc" oninput="setM('description',this.value,true)">${esc(manual.description)}</textarea>
    ${draftSaveFailed
      ? `<p id="m-savenote" class="note-sm" style="margin-top:4px;color:var(--red);font-weight:600">Couldn't auto-save this draft in the browser (storage full or blocked) — keep this tab open until you submit.</p>`
      : `<p id="m-savenote" class="note-sm" style="margin-top:4px">Draft auto-saves in this browser as you type and survives a refresh. It's cleared when anyone signs out on this computer.</p>`}
    ${errorMsg?`<div class="banner err">${esc(errorMsg)}</div>`:""}
    <div style="margin-top:14px"><button class="btn" onclick="submitManual()" ${busy?'disabled':''}>${busy?'<span class="spin"></span> Adding…':'Add case'}</button></div>
  </div>`;
}
function setM(k,v,silent){ manual[k]=v; saveManualDraft(); if(!silent) renderManualBox(); }
function mOnPartyInput(v){ manual.pQuery=v; renderManualBox(); const el=$("mpsearch"); if(el){el.focus();el.setSelectionRange(v.length,v.length);} }
function mToggleRole(r,on){ const s=new Set(manual.pRoles); if(on)s.add(r);else s.delete(r); manual.pRoles=[...s]; saveManualDraft(); renderManualBox(); }
function mPickPartyEmp(id){
  const roles = rolesOrWarn(manual); if(!roles) return;
  for(const r of roles) if(!manual.parties.some(p=>p.id===id&&p.role_in_case===r)) manual.parties.push({type:"employee",id,role_in_case:r});
  manual.pQuery=""; saveManualDraft(); renderManualBox();
}
function mAddParty(){
  const n=($("mpname")?.value||manual.pName||"").trim(); if(!n)return;
  const roles = rolesOrWarn(manual); if(!roles) return;
  for(const r of roles) if(!manual.parties.some(p=>p.type==="customer"&&p.name===n&&p.role_in_case===r)) manual.parties.push({type:"customer",name:n,role_in_case:r});
  manual.pName=""; saveManualDraft(); renderManualBox();
}
function mRmParty(i){ manual.parties.splice(i,1); saveManualDraft(); renderManualBox(); }
async function submitManual(){
  const epoch = sessionEpoch;
  manual.description = $("m-desc")?.value ?? manual.description;
  manual.email = (($("m-email")?.value ?? manual.email)||"").trim();
  errorMsg="";
  if(!manual.description.trim()){ errorMsg="Please paste or describe the report."; renderManualBox(); return; }
  // submit_case_v2 silently SKIPS employee parties no longer in the directory
  // (no error, case still created without them) — catch that here, e.g. a
  // restored draft naming someone who has since been termed.
  const gone = (manual.parties||[]).filter(p => p.type === "employee" && !dirMap[p.id]);
  if(gone.length){ errorMsg = "No longer in the employee directory: " + gone.map(p=>nameOf(p.id)).join(", ")
    + ". Remove that chip (×) — or re-add them by name as a customer entry — then submit."; renderManualBox(); return; }
  // Server only validates reporter email format on NON-manual submissions; a bad
  // address here would queue confirmation emails that bounce in the outbox.
  if(manual.email && !/^\S+@\S+\.\S+$/.test(manual.email)){ errorMsg = "The reporter email doesn't look valid — fix it or leave it blank."; renderManualBox(); return; }
  busy=true; renderManualBox();
  let data, error;
  try {
    ({ data, error } = await sb.rpc("submit_case_v2", {
      p_intake_type:"incident", p_category:manual.category, p_description:manual.description,
      p_anonymous:false, p_location:manual.location||null, p_relationship:null, p_role:null,
      p_contact_email:manual.email||null, p_contact_phone:null, p_parties:manual.parties, p_manual:true, p_incident_date:manual.incidentDate||null }));
  } catch(e) { error = e; }
  if(epoch !== sessionEpoch) return;
  busy=false;
  if(error){ errorMsg = errText(error); renderManualBox(); return; }
  clearManualDraft(); showManual=false; manual=blankIncident(true);
  alert(`Case ${data.ref} added.`); render();
}

// ---- case detail ----
function partyEditHtml(){
  if (!partyEditor.open) return "";
  const q = partyEditor.query.trim().toLowerCase();
  const results = q.length >= 2 ? dirList.filter(d =>
    (d.name||"").toLowerCase().includes(q) ||
    (d.title||"").toLowerCase().includes(q)
  ).slice(0,8) : [];
  return `<div class="party-editor">
    <div style="display:flex;gap:8px;align-items:flex-end;flex-wrap:wrap">
      <div style="min-width:190px"><span class="mini-l">Relationship</span>
        <select onchange="setPartyEditRole(this.value)">
          <option value="subject" ${partyEditor.role==='subject'?'selected':''}>Implicated person</option>
          <option value="victim" ${partyEditor.role==='victim'?'selected':''}>Impacted team member</option>
        </select></div>
      <div style="flex:1;min-width:220px"><span class="mini-l">Find a team member</span>
        <input id="party-edit-search" type="text" value="${esc(partyEditor.query)}" placeholder="Search a name or title…" oninput="onPartyEditInput(this.value)"></div>
    </div>
    ${results.map(d=>`<div class="subj-result" data-employee-id="${esc(d.employee_id)}" onclick="pickPartyEditEmployee(this)">${esc(d.name)} — <span class="muted">${esc(d.title||'')}${d.store?' · '+esc(d.store):''}</span></div>`).join("")}
    <div style="margin-top:10px">${partyEditor.parties.map((p,i)=>`<span class="chip" style="margin:0 6px 6px 0">${esc(nameOf(p.id))} · <i>${esc(rlabel(p.role_in_case))}</i> <a onclick="removePartyEdit(${i})" style="cursor:pointer;color:var(--red);font-weight:700">×</a></span>`).join("") || '<span class="muted">No implicated or impacted employees selected.</span>'}</div>
    <p class="note-sm">Witnesses, reporters, and customer entries are preserved and are not changed by this editor.</p>
    ${partyEditor.err?`<div class="banner err">${esc(partyEditor.err)}</div>`:""}
    <div style="display:flex;gap:8px;margin-top:10px">
      <button class="btn sm" onclick="savePartyEdit()" ${partyEditor.busy?'disabled':''}>${partyEditor.busy?'<span class="spin"></span> Saving…':'Save team members'}</button>
      <button class="btn sm ghost" onclick="togglePartyEditor()" ${partyEditor.busy?'disabled':''}>Cancel</button>
    </div>
  </div>`;
}
function renderPartyEditorInto(){
  const el = $("party-editor");
  if (!el) return;
  el.innerHTML = partyEditHtml();
}
function togglePartyEditor(){
  if (partyEditor.open) {
    partyEditor = { open:false, caseId:null, expectedUpdatedAt:null, parties:[], query:"", role:"subject", busy:false, err:"" };
  } else if (caseExport?.c) {
    partyEditor = {
      open:true, caseId:caseExport.c.id, expectedUpdatedAt:caseExport.c.updated_at,
      parties:(caseExport.parties||[])
        .filter(p=>coalescePartyType(p)==="employee" && ["subject","victim"].includes(p.role_in_case) && p.subject_id)
        .map(p=>({id:p.subject_id,role_in_case:p.role_in_case})),
      query:"", role:"subject", busy:false, err:""
    };
  }
  renderPartyEditorInto();
  const toggle=$("party-editor-toggle");
  if(toggle) toggle.textContent=partyEditor.open ? "Close editor" : "Edit team members";
}
function coalescePartyType(p){ return p.party_type || (p.subject_id ? "employee" : "customer"); }
function partyLineHtml(p){
  return p.party_type==="customer" || (!p.subject_id && p.display_name)
    ? `${esc(p.display_name||"Customer")} (customer, ${esc(rlabel(p.role_in_case))})`
    : `${esc(nameOf(p.subject_id))} (${esc(roleOf(p.subject_id))}${p.role_in_case&&p.role_in_case!=='subject'?', '+esc(rlabel(p.role_in_case)):''})`;
}
function setPartyEditRole(role){ if(["subject","victim"].includes(role)) partyEditor.role=role; }
function onPartyEditInput(value){
  partyEditor.query=value; partyEditor.err=""; renderPartyEditorInto();
  const el=$("party-edit-search"); if(el){ el.focus(); el.setSelectionRange(value.length,value.length); }
}
function pickPartyEditEmployee(el){
  const id=el?.dataset?.employeeId || "";
  if(!id || !dirMap[id]) return;
  if(partyEditor.parties.some(p=>p.id===id && p.role_in_case===partyEditor.role)){
    partyEditor.err="That team member already has this relationship.";
  } else {
    partyEditor.parties.push({id,role_in_case:partyEditor.role});
    partyEditor.query=""; partyEditor.err="";
  }
  renderPartyEditorInto();
}
function removePartyEdit(index){ partyEditor.parties.splice(index,1); partyEditor.err=""; renderPartyEditorInto(); }
async function savePartyEdit(){
  if(!partyEditor.open || partyEditor.busy) return;
  const epoch=sessionEpoch, caseId=partyEditor.caseId;
  const editedParties=partyEditor.parties.map(p=>({
    id:`edited-${p.id}-${p.role_in_case}`, case_id:caseId, subject_id:p.id,
    party_type:"employee", display_name:null, role_in_case:p.role_in_case
  }));
  partyEditor.busy=true; partyEditor.err=""; renderPartyEditorInto();
  const { data, error } = await sb.rpc("update_case_team_members", {
    p_case_id:caseId,
    p_expected_updated_at:partyEditor.expectedUpdatedAt,
    p_parties:partyEditor.parties
  });
  if(epoch !== sessionEpoch) return;
  if(error){
    if(/not authorized/i.test(error.message||"")){
      lastShown=[];
      clearSelectedCaseState();
      alert("Your access to this case changed. Returning to the dashboard.");
      render();
      return;
    }
    partyEditor.busy=false; partyEditor.err=errText(error); renderPartyEditorInto(); return;
  }
  if(caseExport?.c?.id===caseId){
    const preserved=(caseExport.parties||[]).filter(p=>
      !(coalescePartyType(p)==="employee" && ["subject","victim"].includes(p.role_in_case))
    );
    caseExport.parties=[...preserved,...editedParties];
    Object.assign(caseExport.c, {
      handler_id:data?.handler_id ?? caseExport.c.handler_id,
      external:data?.external ?? caseExport.c.external,
      route_reason:data?.route_reason ?? caseExport.c.route_reason,
      updated_at:data?.updated_at ?? caseExport.c.updated_at,
    });
    caseExport.handlerName=caseExport.c.external ? "External advisor" : nameOf(caseExport.c.handler_id);
  }
  partyEditor={ open:false, caseId:null, expectedUpdatedAt:null, parties:[], query:"", role:"subject", busy:false, err:"" };
  if(data?.access_retained===false){
    lastShown=[];
    clearSelectedCaseState();
    alert("Team members updated. This case was rerouted because of a conflict and is no longer available to you.");
    render();
    return;
  }
  const summary=$("party-summary");
  if(summary) summary.innerHTML=(caseExport?.parties||[]).map(partyLineHtml).join(", ")||"—";
  const handler=$("case-handler-summary");
  if(handler) handler.innerHTML=`<b>${esc(caseExport?.handlerName||"—")}</b>${caseExport?.c?.external?' <span class="warnbadge">EXTERNAL</span>':''}`;
  const route=$("case-route-reason");
  if(route) route.textContent=(caseExport?.c?.route_reason||"").replace(/_/g," ");
  renderPartyEditorInto();
  const toggle=$("party-editor-toggle"); if(toggle) toggle.textContent="Edit team members";
}

async function renderCaseDetailInto(el, id){
  const epoch = sessionEpoch;
  const CASE_COLS = "id,ref,category,description,severity,anonymous,handler_id,external,route_reason,state,created_at,closed_at,incident_date,intake_type,location,us_state,reporter_relationship,reporter_role,reporter_display,risk_level,substantiated,substantiated_note,policies,ai_summary,manual_entry,updated_at,accommodation_status,accommodation_start,accommodation_end,accommodation_duration,closure_category,closure_ref";
  const [{data:c}, {data:parties}, {data:events}, {data:tasks}, {data:messages}, {data:notes},
         {data:allegs}, {data:ivs}, {data:actions}, {data:cfiles}] = await Promise.all([
    sb.from("cases").select(CASE_COLS).eq("id",id).maybeSingle(),
    sb.from("case_parties").select("*").eq("case_id",id),
    sb.from("case_events").select("*").eq("case_id",id).order("at",{ascending:true}),
    sb.from("tasks").select("*").eq("case_id",id).order("created_at",{ascending:true}),
    sb.from("messages").select("*").eq("case_id",id).order("created_at",{ascending:true}),
    sb.from("case_notes").select("*").eq("case_id",id).order("created_at",{ascending:true}),
    sb.from("case_allegations").select("*").eq("case_id",id).order("created_at",{ascending:true}),
    sb.from("case_interviews").select("*").eq("case_id",id).order("created_at",{ascending:true}),
    sb.from("corrective_actions").select("*").eq("case_id",id).order("created_at",{ascending:true}),
    // email-intake attachment metadata (migration 019) — degrades to empty pre-019
    sb.from("case_files").select("*").eq("case_id",id).order("created_at",{ascending:true}),
  ]);
  if (epoch !== sessionEpoch || selected !== id || !el.isConnected) return;  // stale-paint/session guard
  caseAllegs = allegs || [];   // used by the close modal gate
  if(!c){ el.innerHTML=`<button class="back" onclick="closeCase()">← Back</button><div class="card"><div class="banner warn">This case isn't available to you.</div></div>`; return; }
  // evidence list (bucket may not exist pre-v2 — degrade quietly)
  sb.storage.from("evidence").list(id).then(({data,error})=>{
    if(epoch !== sessionEpoch || selected !== id) return;
    evidence = error ? {list:[],err:"Evidence storage isn't set up yet (v2 backend)."} : {list:data||[],err:""};
    const ev=$("ev-list"); if(ev) ev.innerHTML = evidenceHtml(id);
  });
  const handlerName = c.external ? "External advisor" : nameOf(c.handler_id);
  const isReq = c.intake_type === "request";
  // everything the .zip export needs — snapshot of what this view fetched
  caseExport = { c, parties: parties||[], events: events||[], tasks: tasks||[], messages: messages||[],
                 notes: notes||[], allegations: allegs||[], interviews: ivs||[], actions: actions||[],
                 files: cfiles||[], handlerName };
  // Loose transitions for both lifecycles; Reopened only offered from Closed.
  const nexts = isReq
    ? (c.state==="Closed" ? ["Assigned"] : REQ_STATES.filter(s=>s!==c.state))
    : (c.state==="Closed" ? ["Reopened"] : INCIDENT_STATES.filter(s=>s!==c.state));
  const canClose = c.state !== "Closed";
  const now = Date.now();
  el.innerHTML = `<button class="back" onclick="closeCase()">← Back to dashboard</button>
  <div class="card">
    <div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap"><span class="ref" style="font-size:16px">${esc(c.ref)}</span>${pill(c.state)}${riskPill(caseRisk(c))}${isReq&&c.accommodation_status?accPill(c.accommodation_status):''}${!isReq&&c.substantiated===true?'<span class="chip">Substantiated</span>':!isReq&&c.substantiated===false?'<span class="chip soft">Unsubstantiated</span>':''}${c.closure_category?`<span class="chip">Closure: ${esc(c.closure_category)}${c.closure_ref?' → '+esc(c.closure_ref):''}</span>`:''}
      <button class="btn sm ghost" style="margin-left:auto" onclick="exportCaseZip()">Export case (.zip)</button></div>
    <h2 class="section" style="margin-top:6px">${esc(c.category)}</h2>
    <div class="row">
      <div class="col">
        <div class="kv"><span class="k">${L(c,'reporter')}</span>${c.anonymous?'<span class="chip">Anonymous — contact info hidden, system emails them updates</span>':`<b>${esc(c.reporter_display||'—')}</b>`}</div>
        <div class="kv"><span class="k">Location</span><span>${esc(c.location||'—')}</span></div>
        ${!isReq?`<div class="kv"><span class="k">Occurred</span><span>${c.incident_date?esc(c.incident_date):'—'}</span></div>
        <div class="kv"><span class="k">Relationship</span><span>${esc(c.reporter_relationship||'—')}${c.reporter_role?' · '+esc(c.reporter_role):''}</span></div>
        <div class="kv"><span class="k">Involved</span><span id="party-summary">${(parties||[]).map(partyLineHtml).join(", ")||'—'}</span> <button id="party-editor-toggle" class="btn sm ghost" style="margin-left:8px" onclick="togglePartyEditor()">${partyEditor.open?'Close editor':'Edit team members'}</button></div>
        <div id="party-editor">${partyEditor.open&&partyEditor.caseId===c.id?partyEditHtml():''}</div>`:""}
        <div class="kv"><span class="k">${L(c,'handler')}</span><span id="case-handler-summary"><b>${esc(handlerName)}</b>${c.external?' <span class="warnbadge">EXTERNAL</span>':''}</span>
          <button class="btn sm ghost" style="margin-left:8px" onclick="toggleReassign()">${showReassign?'Cancel':'Reassign'}</button></div>
        ${showReassign?`<div class="reassign">
          <select id="ra-to">${hrTeam.filter(t=>t.employee_id!==c.handler_id).map(t=>`<option value="${esc(t.employee_id)}">${esc(nameOf(t.employee_id))}</option>`).join("")}</select>
          <input id="ra-why" type="text" placeholder="Reason (optional)">
          <button class="btn sm" onclick="doReassign('${c.id}')">Confirm reassignment</button>
        </div>`:""}
        <div class="kv"><span class="k">Route reason</span><span id="case-route-reason">${esc((c.route_reason||'').replace(/_/g,' '))}</span></div>
        <div class="kv"><span class="k">${L(c,'risk')}</span><span>
          <select id="risk-sel" style="width:auto;padding:5px 34px 5px 8px">${["",...RISKS].map(r=>`<option value="${r}" ${caseRisk(c)===r?'selected':''}>${r||'— unset —'}</option>`).join("")}</select>
          <button class="btn sm sec" onclick="saveRisk('${c.id}')">Save</button></span></div>
      </div>
      <div class="col"><div class="kv"><span class="k">Description</span></div><div class="banner desc">${esc(c.description)}</div>
        ${c.ai_summary?`<div class="kv" style="margin-top:8px"><span class="k">AI review</span></div><div class="banner info">${esc(c.ai_summary)}</div>`:""}</div>
    </div>
    ${!isReq?`<label>Allegations &amp; Policies Potentially Implicated</label>
    <div class="alleg-wrap">
      <span class="mini-l">Allegations — each needs a finding before the case can close</span>
      ${(allegs||[]).length?(allegs||[]).map(a=>`
        <div class="alleg-row">
          <b>${esc(a.allegation)}</b>
          <select onchange="setFindingUI('${a.id}',this.value)" style="width:auto;min-width:190px">
            <option value="">— finding pending —</option>
            ${FINDINGS.map(f=>`<option ${a.finding===f?'selected':''}>${f}</option>`).join("")}
          </select>
          <a onclick="removeAllegationUI('${a.id}')" style="cursor:pointer;color:var(--red);font-weight:700">×</a>
        </div>`).join(""):'<p class="muted" style="margin:6px 0">No allegations recorded yet.</p>'}
      <div style="display:flex;gap:8px;flex-wrap:wrap;margin-top:8px">
        <select id="alg-sel" style="width:auto;min-width:200px">${ALLEGATION_TYPES.map(a=>`<option>${a}</option>`).join("")}<option value="__custom">Other (type below)…</option></select>
        <input id="alg-custom" type="text" placeholder="Custom allegation (if Other)" style="width:auto;flex:1;min-width:160px">
        <button class="btn sm sec" onclick="addAllegationUI('${c.id}')">Add allegation</button>
      </div>
      <span class="mini-l" style="margin-top:14px">Policies potentially implicated</span>
      <div style="margin:6px 0">${(c.policies||'').split(';').map(s=>s.trim()).filter(Boolean).map(p=>`<span class="chip" style="margin:0 6px 6px 0">${esc(p)} <a data-case="${esc(c.id)}" data-policy="${esc(p)}" onclick="removePolicyChipFromElement(this)" style="cursor:pointer;color:var(--red);font-weight:700">×</a></span>`).join("")||'<span class="muted">None selected.</span>'}</div>
      <div style="display:flex;gap:8px;flex-wrap:wrap">
        <select id="pol-sel" style="width:auto;min-width:220px">${POLICY_LIST.map(p=>`<option>${p}</option>`).join("")}</select>
        <button class="btn sm sec" onclick="addPolicyChip('${c.id}')">Add policy</button>
      </div>
    </div>`:""}
     <div class="divider"></div>
     <b style="font-size:13px">${isReq?'Move this request to':'Advance case state'}</b>
     <p class="note-sm" style="margin:4px 0 0">Click a state, then click <b>Save</b> to confirm — nothing is recorded until you save. Moving backwards is allowed.</p>
     <div class="transition-current"><span class="mini-l">Current state</span>${pill(c.state)}</div>
     <div style="margin-top:8px">
      ${nexts.map(n=> (pendingAdvance && pendingAdvance.id===c.id && pendingAdvance.to===n)
        ? `<span style="display:inline-flex;gap:6px;margin-right:8px;margin-bottom:6px;align-items:center">
             <button class="btn sm" onclick="doAdvance('${c.id}','${n}')">Save — move to ${stlabel(n)}</button>
             <button class="btn sm ghost" onclick="cancelAdvance()">Cancel</button></span>`
        : `<button class="btn sm sec" style="margin-right:8px;margin-bottom:6px" onclick="doAdvance('${c.id}','${n}')">→ ${stlabel(n)}</button>`).join("")}
      ${canClose?`<button class="btn sm danger" onclick="openCloseModal('${c.id}','${isReq?'request':'incident'}')">${isReq?'Close request…':'Close case…'}</button>`:""}
      ${!nexts.length&&!canClose?'<span class="muted">Case is closed.</span>':""}
    </div>
  </div>
  ${isReq?`<div class="card">
    <b>Accommodation</b> <span class="chip">for reporting</span>
    <div class="row" style="margin-top:14px">
      <div class="col" style="min-width:210px"><span class="mini-l">Outcome / status</span>
        <select id="acc-status">${["",...ACC_STATUS].map(s=>`<option value="${esc(s)}" ${c.accommodation_status===s?'selected':''}>${s||'— not yet decided —'}</option>`).join("")}</select></div>
      <div class="col" style="min-width:150px"><span class="mini-l">Duration</span>
        <select id="acc-dur">${["",...ACC_DURATION].map(s=>`<option value="${esc(s)}" ${c.accommodation_duration===s?'selected':''}>${s||'— unset —'}</option>`).join("")}</select></div>
      <div class="col" style="min-width:150px"><span class="mini-l">Start date</span>
        <input id="acc-start" type="date" value="${esc(c.accommodation_start||'')}"></div>
      <div class="col" style="min-width:150px"><span class="mini-l">End date</span>
        <input id="acc-end" type="date" value="${esc(c.accommodation_end||'')}"></div>
    </div>
    <div style="margin-top:14px"><button class="btn sm" onclick="saveAccommodation('${c.id}')">Save accommodation details</button></div>
  </div>`:""}
  <div class="row">
    <div class="col card"><b>${L(c,'evidence')}</b>
      <div id="ev-list" style="margin-top:10px">${evidenceHtml(id)}</div>
      <div style="margin-top:10px;display:flex;gap:8px;align-items:center"><input id="ev-file" type="file" multiple style="flex:1"><button class="btn sm sec" onclick="uploadCaseEvidence('${c.id}')">Upload</button></div>
    </div>
    <div class="col card"><b>Follow-up tasks &amp; SLAs</b><div style="margin-top:10px">
      ${(tasks||[]).length?tasks.map(t=>{const over=t.status==="open"&&t.due_at&&new Date(t.due_at).getTime()<now;
        return `<div class="task">
          <span style="${t.status==='done'?'text-decoration:line-through;color:var(--grey)':''}">${esc(t.title)}</span>
          <span class="due" style="color:${over?'var(--red)':'var(--grey)'}">${t.status==='done'?'Done':(over?'Overdue':'Due '+fmt(t.due_at))}</span>
          <button class="btn sm ghost" onclick="toggleTask('${t.id}',${t.status!=='done'})">${t.status==='done'?'Reopen':'Mark done'}</button></div>`;}).join(""):'<span class="muted">No tasks.</span>'}
    </div></div>
  </div>
  ${(cfiles||[]).length?`<div class="card"><b>Files</b> <span class="chip">received by email</span>
    <div style="margin-top:10px">${(cfiles||[]).map(f=>`<div class="task">
      <span>${esc(f.file_name)}<span class="muted" style="font-size:11px"> · ${fmtBytes(f.size_bytes)}${f.source==='email'?' · email':''}${f.uploaded_by?' · from '+esc(f.uploaded_by):''}</span></span>
      <span class="due">${f.created_at?fmt(f.created_at):''}</span>
      ${f.storage_path
        ? `<button class="btn sm ghost" data-p="${esc(f.storage_path)}" data-n="${esc(f.file_name)}" onclick="caseFileDownload(this.dataset.p,this.dataset.n)">Download</button>`
        : (f.email_fallback_url && f.email_fallback_url.startsWith('https://')  // scheme guard (QC 8/31): never render a javascript:/data: href
            ? `<a class="btn sm ghost" href="${esc(f.email_fallback_url)}" target="_blank" rel="noopener noreferrer">Open in mailbox</a>`
            : '<span class="muted" style="font-size:11px">stored in mailbox</span>')}
    </div>`).join("")}
    <p class="note-sm" style="margin-top:8px">Files that arrived by email. Ones too large to store open in the peoplesupport@ mailbox instead (original emails are retained there).</p>
    </div></div>`:""}
  ${!isReq?`<div class="card"><b>Interviews</b> <span class="chip">internal — HR team only</span>
    <p class="note-sm" style="margin-top:4px">Prepare questions in Notes before the call and type during it — notes save when you click away from the box (and with Save). Unlike evidence, these stay editable.</p>
    <div style="margin-top:10px">
    ${(ivs||[]).length?(ivs||[]).map(iv=>`
      <div class="iv-row" id="iv-${iv.id}">
        <div class="iv-grid">
          <span><span class="mini-l">Person interviewed</span><input id="iv-name-${iv.id}" type="text" value="${esc(iv.interviewee)}"></span>
          <span><span class="mini-l">Role in case</span><select id="iv-role-${iv.id}">${[...new Set([...PARTY_ROLES, ...(iv.role_in_case?[iv.role_in_case]:[]), "Other"])].map(r=>`<option value="${r}" ${iv.role_in_case===r?'selected':''}>${rlabel(r)}</option>`).join("")}</select></span>
          <span><span class="mini-l">Date</span><input id="iv-date-${iv.id}" type="date" value="${esc(iv.interview_date||'')}"></span>
          <span><span class="mini-l">Interviewer</span><input id="iv-by-${iv.id}" type="text" value="${esc(iv.interviewer||'')}"></span>
          <span><span class="mini-l">Status</span><select id="iv-status-${iv.id}">${INTERVIEW_STATUS.map(s=>`<option ${iv.status===s?'selected':''}>${s}</option>`).join("")}</select></span>
          <span><span class="mini-l">Follow-up needed</span><input id="iv-fu-${iv.id}" type="text" value="${esc(iv.follow_up||'')}" placeholder="e.g. get schedule records"></span>
        </div>
        <span class="mini-l" style="margin-top:8px">Questions &amp; notes</span>
        <textarea id="iv-notes-${iv.id}" style="min-height:90px" onblur="saveInterviewUI('${c.id}','${iv.id}',true)">${esc(iv.notes||'')}</textarea>
        <div style="display:flex;gap:8px;margin-top:8px">
          <button class="btn sm sec" onclick="saveInterviewUI('${c.id}','${iv.id}')">Save</button>
          <span class="muted" id="iv-saved-${iv.id}" style="font-size:12px;align-self:center"></span>
          <button class="btn sm ghost" style="margin-left:auto" onclick="deleteInterviewUI('${iv.id}')">Remove</button>
        </div>
      </div>`).join(""):'<p class="muted">No interviews yet.</p>'}
    </div>
    <div class="divider"></div>
    <span class="mini-l">Add an interview</span>
    <div class="iv-grid" style="margin-top:6px">
      <span><span class="mini-l">Person interviewed</span><input id="ni-name" type="text" placeholder="Name"></span>
      <span><span class="mini-l">Role in case</span><select id="ni-role">${[...PARTY_ROLES,"Other"].map(r=>`<option value="${r}">${rlabel(r)}</option>`).join("")}</select></span>
      <span><span class="mini-l">Date</span><input id="ni-date" type="date"></span>
      <span><span class="mini-l">Interviewer</span><input id="ni-by" type="text" value="${esc(me?.name||'')}"></span>
    </div>
    <div style="margin-top:10px"><button class="btn sm" onclick="addInterviewUI('${c.id}')">Add interview</button></div>
  </div>
  <div class="card"><b>Corrective Actions</b> <span class="chip">restricted — HR team only</span>
    <div style="margin-top:10px">
    ${(actions||[]).length?(actions||[]).map(a=>`
      <div class="iv-row">
        <div class="iv-grid">
          <span><span class="mini-l">Action type</span><select id="ca-type-${a.id}">${CORRECTIVE_TYPES.map(t=>`<option ${a.action_type===t?'selected':''}>${t}</option>`).join("")}</select></span>
          <span><span class="mini-l">Responsible person</span><input id="ca-resp-${a.id}" type="text" value="${esc(a.responsible||'')}"></span>
          <span><span class="mini-l">Due date</span><input id="ca-due-${a.id}" type="date" value="${esc(a.due_date||'')}"></span>
          <span><span class="mini-l">Completed</span><input id="ca-done-${a.id}" type="date" value="${esc(a.completed_date||'')}"></span>
        </div>
        <span class="mini-l" style="margin-top:8px">Notes</span>
        <input id="ca-notes-${a.id}" type="text" value="${esc(a.notes||'')}">
        <div style="display:flex;gap:8px;margin-top:8px">
          <button class="btn sm sec" onclick="saveActionUI('${c.id}','${a.id}')">Save</button>
          <button class="btn sm ghost" style="margin-left:auto" onclick="deleteActionUI('${a.id}')">Remove</button>
        </div>
      </div>`).join(""):'<p class="muted">No corrective actions recorded.</p>'}
    </div>
    <div class="divider"></div>
    <div class="iv-grid">
      <span><span class="mini-l">Action type</span><select id="na-type">${CORRECTIVE_TYPES.map(t=>`<option>${t}</option>`).join("")}</select></span>
      <span><span class="mini-l">Responsible person</span><input id="na-resp" type="text" placeholder="Who carries it out"></span>
      <span><span class="mini-l">Due date</span><input id="na-due" type="date"></span>
    </div>
    <div style="margin-top:10px"><button class="btn sm" onclick="addActionUI('${c.id}')">Add corrective action</button></div>
  </div>`:""}
  <div class="card"><div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap"><b>HR notes</b> <span class="chip">internal — visible to the HR team only</span>
    <button class="btn sm ghost" style="margin-left:auto" onclick="toggleGuide()">${showGuide?'Hide guide':L(c,'guide')}</button></div>
    ${showGuide?(isReq?processGuideHtml():interviewGuideHtml()):""}
    <div style="margin-top:12px">${(notes||[]).length?notes.map(n=>{const w=dirList.find(d=>(d.email||'').toLowerCase()===(n.author_email||'').toLowerCase());return `<div class="hrnote"><div class="t">${esc(w?w.name:n.author_email)} · ${fmt(n.created_at)}</div>${esc(n.body)}</div>`;}).join(""):'<span class="muted">No notes yet.</span>'}</div>
    <div style="display:flex;gap:8px;margin-top:12px"><textarea id="hr-note" placeholder="Write your thoughts on this case…" style="min-height:60px;flex:1"></textarea><button class="btn sec" onclick="addNote('${c.id}')" style="align-self:flex-end">Add note</button></div>
  </div>
  <div class="card"><b>Case timeline (audit log)</b><ul class="timeline" style="margin-top:10px">
    ${(events||[]).map(e=>`<li><div class="t">${fmt(e.at)} · ${esc(e.type)}</div><div class="e">${esc(e.note)}</div></li>`).join("")}
  </ul></div>
  <div class="card"><b>Messages ${c.anonymous?'<span class="chip">relayed — reporter stays anonymous</span>':''}</b>
    <div class="msgwrap" style="margin:12px 0">${(messages||[]).length?messages.map(m=>`<div class="msg ${m.sender_type}"><div class="who">${m.sender_type==='handler'?esc(handlerName):m.sender_type==='email'?('Email · '+esc(m.sender_email||'external')):((c.anonymous?'Anonymous reporter':esc(c.reporter_display||'Reporter'))+(m.via_email?' · via email (unverified sender)':''))}</div>${linkify(m.body)}</div>`).join(""):'<span class="muted">No messages yet.</span>'}</div>
    <p class="note-sm">Messages are also emailed to the reporter automatically${c.anonymous?" — without revealing their address to you":""}.</p>
    <div style="display:flex;gap:8px"><input id="hmsg" type="text" placeholder="Message the reporter…"><button class="btn" onclick="sendHandlerMsg('${c.id}')">Send</button></div>
  </div>
  ${closeModal.open?renderCloseModal():""}`;
}
function evidenceHtml(caseId){
  if(evidence.err) return `<span class="muted">${esc(evidence.err)}</span>`;
  if(!evidence.list.length) return '<span class="muted">No evidence uploaded.</span>';
  return evidence.list.map(f=>`<div class="task"><span>${esc(f.name.replace(/^\d+_/,''))}</span>
      <span class="due">${f.created_at?fmt(f.created_at):''}</span>
      <button class="btn sm ghost" data-n="${esc(f.name)}" onclick="evDownload('${caseId}',this.dataset.n)">Download</button></div>`).join("")
    + `<p class="note-sm" style="margin-top:8px">Files are locked once submitted — you can download them but not edit or replace them (audit integrity). Use the Interviews section for working notes and questions.</p>`;
}
// ---- email-intake files (case_files, migration 019) -------------------------
const fmtBytes = n => (n==null || isNaN(n)) ? "—"
  : n < 1024 ? `${n} B`
  : n < 1048576 ? `${(n/1024).toFixed(0)} KB`
  : `${(n/1048576).toFixed(1)} MB`;
async function caseFileDownload(path, name){
  // service-role wrote these under case_<uuid>/… — handlers read via the
  // evidence_email_select storage policy (019).
  const { data, error } = await sb.storage.from("evidence").download(path);
  if(error || !data){ alert("Could not download this file: " + (error?.message||"unknown error")); return; }
  downloadBlob(data, name || path.split("/").pop());
}
async function evDownload(caseId, fname){
  const { data, error } = await sb.storage.from("evidence").createSignedUrl(`${caseId}/${fname}`, 120);
  if(error || !data?.signedUrl){ alert("Could not create a download link: " + (error?.message||"unknown error")); return; }
  window.open(data.signedUrl, "_blank");
}
async function uploadCaseEvidence(caseId){
  const files = Array.from($("ev-file")?.files||[]);
  if(!files.length) return;
  for(const f of files){
    if(!(await uploadEvidenceFile(caseId, f))){ alert("Upload failed. Please try again."); return; }
  }
  render();
}
async function uploadEvidenceFile(caseId, file){
  try {
    const safeName = String(file?.name || "attachment").replace(/[\\/]/g,"_");
    const unique = globalThis.crypto?.randomUUID?.() || `${Date.now()}_${Math.random().toString(36).slice(2)}`;
    const { error } = await sb.storage.from("evidence").upload(`${caseId}/${unique}_${safeName}`, file);
    return !error;
  } catch {
    return false;
  }
}
// ---- allegations, policies, interviews, corrective actions (v4) ----
let caseAllegs = [];
async function addAllegationUI(caseId){
  let v = $("alg-sel")?.value;
  if(v === "__custom") v = ($("alg-custom")?.value || "").trim();
  if(!v) return;
  const { error } = await sb.rpc("add_allegation", { p_case_id: caseId, p_allegation: v });
  if(error){ alert(errText(error)); return; }
  render();
}
async function setFindingUI(id, f){
  const { error } = await sb.rpc("set_finding", { p_id: id, p_finding: f || null });
  if(error){ alert(errText(error)); return; }
  render();
}
async function removeAllegationUI(id){
  const { error } = await sb.rpc("remove_allegation", { p_id: id });
  if(error){ alert(errText(error)); return; }
  render();
}
async function addPolicyChip(caseId){
  const v = $("pol-sel")?.value; if(!v) return;
  const { data } = await sb.from("cases").select("policies").eq("id", caseId).maybeSingle();
  const cur = (data?.policies || "").split(";").map(s=>s.trim()).filter(Boolean);
  if(!cur.includes(v)) cur.push(v);
  const { error } = await sb.rpc("set_policies", { p_case_id: caseId, p_policies: cur.join("; ") });
  if(error){ alert(errText(error)); return; }
  render();
}
async function removePolicyChip(caseId, p){
  const { data } = await sb.from("cases").select("policies").eq("id", caseId).maybeSingle();
  const cur = (data?.policies || "").split(";").map(s=>s.trim()).filter(Boolean).filter(x=>x!==p);
  const { error } = await sb.rpc("set_policies", { p_case_id: caseId, p_policies: cur.join("; ") });
  if(error){ alert(errText(error)); return; }
  render();
}
// Interviews: explicit Save and notes-blur autosave both write straight to the DB.
// Neither triggers a re-render, so typing/scroll position is never lost mid-interview.
async function saveInterviewUI(caseId, id, silent){
  const g = k => $(`iv-${k}-${id}`)?.value ?? null;
  const { error } = await sb.rpc("save_interview", {
    p_id: id, p_case_id: caseId,
    p_interviewee: g("name"), p_role: g("role"), p_date: g("date") || null,
    p_interviewer: g("by"), p_status: g("status"),
    p_notes: $(`iv-notes-${id}`)?.value ?? null, p_follow_up: g("fu") });
  const s = $(`iv-saved-${id}`);
  if(error){ if(s) s.textContent = "Save failed"; if(!silent) alert(errText(error)); return; }
  if(s) s.textContent = "Saved " + new Date().toLocaleTimeString();
}
async function addInterviewUI(caseId){
  const name = ($("ni-name")?.value || "").trim();
  if(!name){ alert("Enter the name of the person interviewed."); return; }
  const { error } = await sb.rpc("save_interview", {
    p_id: null, p_case_id: caseId, p_interviewee: name,
    p_role: $("ni-role")?.value ?? null, p_date: $("ni-date")?.value || null,
    p_interviewer: $("ni-by")?.value ?? null, p_status: "Scheduled",
    p_notes: null, p_follow_up: null });
  if(error){ alert(errText(error)); return; }
  render();
}
async function deleteInterviewUI(id){
  if(!confirm("Remove this interview (including its notes)?")) return;
  const { error } = await sb.rpc("delete_interview", { p_id: id });
  if(error){ alert(errText(error)); return; }
  render();
}
async function saveActionUI(caseId, id){
  const g = k => $(`ca-${k}-${id}`)?.value ?? null;
  const { error } = await sb.rpc("save_corrective_action", {
    p_id: id, p_case_id: caseId, p_action_type: g("type"),
    p_responsible: g("resp"), p_due: g("due") || null,
    p_completed: g("done") || null, p_notes: g("notes") });
  if(error){ alert(errText(error)); return; }
  render();
}
async function addActionUI(caseId){
  const { error } = await sb.rpc("save_corrective_action", {
    p_id: null, p_case_id: caseId, p_action_type: $("na-type")?.value,
    p_responsible: $("na-resp")?.value ?? null, p_due: $("na-due")?.value || null,
    p_completed: null, p_notes: null });
  if(error){ alert(errText(error)); return; }
  render();
}
async function deleteActionUI(id){
  if(!confirm("Remove this corrective action?")) return;
  const { error } = await sb.rpc("delete_corrective_action", { p_id: id });
  if(error){ alert(errText(error)); return; }
  render();
}
async function toggleTask(id, done){
  const { error } = await sb.rpc("set_task_status", { p_task_id: id, p_done: done });
  if(error){ alert(errText(error)); return; }
  render();
}
async function saveRisk(id){
  const v = $("risk-sel")?.value; if(!v) return;
  const { error } = await sb.rpc("set_risk_level",{ p_case_id:id, p_risk:v });
  if(error){ alert(errText(error)); return; } render();
}
async function savePolicies(id){
  const v = $("pol")?.value ?? "";
  const { error } = await sb.rpc("set_policies",{ p_case_id:id, p_policies:v });
  if(error){ alert(errText(error)); return; } render();
}
function toggleGuide(){ showGuide=!showGuide; render(); }
// Placeholder until the approved Interactive Process Guide text is available.
function processGuideHtml(){
  return `<div class="guide">
    <div class="g-sec"><span class="mini-l">Interactive Process Guide</span>
      Approved guide content is still pending. Once available, it will appear here in the
      same format as the interview guide for incident cases.</div>
    <div class="g-sec"><span class="mini-l">In the meantime, log these in your notes</span>
      Date of each contact · who you spoke with · what was requested · what information or
      documentation is still outstanding · options discussed · the decision and why.</div>
  </div>`;
}
async function saveAccommodation(id){
  const { error } = await sb.rpc("set_accommodation", {
    p_case_id:id,
    p_status:   $("acc-status")?.value || null,
    p_start:    $("acc-start")?.value  || null,
    p_end:      $("acc-end")?.value    || null,
    p_duration: $("acc-dur")?.value    || null });
  if(error){ alert(errText(error)); return; }
  render();
}
function toggleReassign(){ showReassign=!showReassign; render(); }
async function doReassign(id){
  const to = $("ra-to")?.value; if(!to) return;
  const why = $("ra-why")?.value || "";
  const { error } = await sb.rpc("reassign_case",{ p_case_id:id, p_to:to, p_reason:why });
  if(error){ alert(errText(error)); return; }
  showReassign=false; render();
}
// From the approved branded ER statement template (July 2026) — the interview
// guide used when discussing a report on a call. Shown next to HR notes so the
// handler knows what to capture.
function interviewGuideHtml(){
  return `<div class="guide">
    <div class="g-sec"><span class="mini-l">Log these details in your notes</span>
      Date &amp; time of the call · who you interviewed (name, title, store) · interview duration · remote or in person · the implicated person.</div>
    <div class="g-sec"><span class="mini-l">Introduction — say to the interviewee</span>
      <ul><li>Brief intro: your name, title, and role in the investigation.</li>
      <li>Reason for the conversation — if they're implicated: "We're looking into a concern that was reported. We're not saying what was reported is true, but we need to ask for your account."</li></ul></div>
    <div class="g-sec"><span class="mini-l">Explain the HR approach</span>
      <ul><li>We don't assume the report is true — it's the starting point for the investigation.</li>
      <li>Recommendations are based only on what we can substantiate (factual / provable).</li>
      <li>Unable to substantiate or inconclusive ≠ we don't believe it could have happened.</li>
      <li>Corrective actions are constrained to what we can prove or deduce.</li></ul></div>
    <div class="g-sec"><span class="mini-l">Confidentiality — say to the interviewee</span>
      No one who doesn't need access will see this statement. Key Support Center HR people or legal counsel may reference it if needed; beyond that we do our best to keep it confidential.</div>
    <div class="g-sec"><span class="mini-l">Questions — record each response below</span>
      <ul><li><b>Open with:</b> "How would you describe the overall working environment in your store/area?"</li>
      <li><b>Then 5–6 specific questions about this case</b> — prepare them from the description and evidence before the call.</li>
      <li><b>Always close with:</b> "Is there anything else that you feel is important for me to know, or that I should have asked you?"</li></ul></div>
  </div>`;
}
async function addNote(id){
  const v = $("hr-note")?.value.trim(); if(!v) return;
  const { error } = await sb.rpc("add_case_note",{ p_case_id:id, p_body:v });
  if(error){ alert(errText(error)); return; }
  render();
}
// Two-click state change (8/18): the first click only ARMS the move (nothing is
// written or tracked); the second "Save" click actually calls advance_state.
// Backwards moves are allowed. Every confirmed change is logged server-side in
// case_events with the user who made it (advance_state records the actor email).
async function doAdvance(id,to){
  if(!(pendingAdvance && pendingAdvance.id===id && pendingAdvance.to===to)){ pendingAdvance={id,to}; render(); return; }
  pendingAdvance=null;
  const {error}=await sb.rpc("advance_state",{p_case_id:id,p_to:to}); if(error)alert(errText(error)); render();
}
function cancelAdvance(){ pendingAdvance=null; render(); }
async function sendHandlerMsg(id){ const v=$("hmsg")?.value.trim(); if(!v)return; const {error}=await sb.rpc("post_handler_message",{p_case_id:id,p_body:v}); if(error)alert(errText(error)); render(); }

// ---- close-case modal (findings/outcome + closure categorization REQUIRED) ----
function openCloseModal(caseId, kind){ closeModal={open:true,caseId,kind:kind||"incident",sub:null,status:"",note:"",cat:"",ref:""}; render(); }
function cancelCloseModal(){ closeModal={open:false,caseId:null,kind:"incident",sub:null,status:"",note:"",cat:"",ref:""}; render(); }
// Each handler captures the free-text inputs FIRST — render() repaints the
// modal and would wipe them (same lesson as applyFilters/#flt-q).
function captureCloseInputs(){ closeModal.note=$("close-note")?.value??closeModal.note; closeModal.ref=$("close-ref")?.value??closeModal.ref; }
function setCloseSub(v){ closeModal.sub=v; captureCloseInputs(); render(); }
function setCloseStatus(v){ closeModal.status=v; captureCloseInputs(); render(); }
function setCloseCat(v){ captureCloseInputs(); closeModal.cat=v; render(); }
function renderCloseModal(){
  const isReq = closeModal.kind==="request";
  const missing = caseAllegs.filter(a=>!a.finding).length;
  const canCloseInc = caseAllegs.length > 0 && missing === 0;
  return `<div class="modal-overlay" onclick="if(event.target===this)cancelCloseModal()">
    <div class="modal">
      <h2 class="section" style="font-size:17px">${isReq?'Close this request':'Close this case'}</h2>
      ${isReq
        ? `<p class="muted">Record the outcome before closing — this is what gets reported on.</p>
           <label>Accommodation outcome</label>
           <select onchange="setCloseStatus(this.value)">
             <option value="">— select an outcome —</option>
             ${ACC_STATUS.map(s=>`<option ${closeModal.status===s?'selected':''}>${s}</option>`).join("")}
           </select>`
        : `<p class="muted">A case closes on its findings. Every allegation needs a finding recorded first.</p>
           ${caseAllegs.length
             ? `<ul style="margin:10px 0;padding-left:18px">${caseAllegs.map(a=>`<li style="margin-bottom:4px"><b>${esc(a.allegation)}</b> — ${a.finding?esc(a.finding):'<span style="color:var(--danger)">finding pending</span>'}</li>`).join("")}</ul>`
             : `<div class="banner warn">No allegations recorded yet — add at least one (with a finding) in the Allegations section, then close.</div>`}`}
      <label>Closure categorization <span class="muted" style="font-weight:400;text-transform:none;letter-spacing:0">(required — why is this ${isReq?'request':'case'} closing?)</span></label>
      <select onchange="setCloseCat(this.value)">
        <option value="">— select a categorization —</option>
        ${CLOSURE_CATEGORIES.map(k=>`<option ${closeModal.cat===k?'selected':''}>${k}</option>`).join("")}
      </select>
      ${closeModal.cat==='Duplicate'?`
      <label>Duplicate of case #</label>
      <input id="close-ref" type="text" placeholder="e.g. EB-2026-0142" value="${esc(closeModal.ref)}">
      <p class="note-sm" style="margin-top:4px">Required — the ref of the case this one duplicates.</p>`:""}
      <label>Closing note (optional)</label>
      <textarea id="close-note" style="min-height:70px">${esc(closeModal.note)}</textarea>
      <div style="margin-top:14px;display:flex;gap:8px;justify-content:flex-end">
        <button class="btn ghost" onclick="cancelCloseModal()">Cancel</button>
        <button class="btn" ${(!closeModal.cat || (isReq ? !closeModal.status : !canCloseInc))?'disabled':''} onclick="confirmClose()">${isReq?'Close request':'Close case'}</button>
      </div>
    </div></div>`;
}
async function confirmClose(){
  const isReq = closeModal.kind==="request";
  if(isReq ? !closeModal.status : !(caseAllegs.length && caseAllegs.every(a=>a.finding))) return;
  if(!closeModal.cat) return;
  const dupRef = ($("close-ref")?.value ?? closeModal.ref).trim();
  if(closeModal.cat==='Duplicate' && !dupRef){ alert("Enter the case # this one duplicates."); return; }
  const note = $("close-note")?.value || "";
  if(isReq){
    // write the outcome first (close_case refuses without one). Existing dates/duration
    // are read back off the accommodation panel so saving here can't wipe them.
    const { error:e1 } = await sb.rpc("set_accommodation",{
      p_case_id:closeModal.caseId, p_status:closeModal.status,
      p_start:$("acc-start")?.value||null, p_end:$("acc-end")?.value||null,
      p_duration:$("acc-dur")?.value||null });
    if(e1){ alert(errText(e1)); return; }
  }
  // new args need migration 017 (drops the old 3-arg close_case signature)
  const { error } = await sb.rpc("close_case",{ p_case_id:closeModal.caseId, p_substantiated:null, p_note:note,
    p_closure_category:closeModal.cat, p_closure_ref:closeModal.cat==='Duplicate'?dupRef:null });
  if(error){ alert(errText(error)); return; }
  cancelCloseModal();
}

// ---------------- EMPLOYEE MENTION LOOKUP ----------------
function renderLookup(){
  const results = lookup.query.length>=2 && !lookup.picked ? dirList.filter(d =>
      (d.name||"").toLowerCase().includes(lookup.query.toLowerCase())).slice(0,8) : [];
  return `<div class="card" style="max-width:760px;margin:0 auto">
    <h2 class="section">Employee mention lookup</h2>
    <p class="muted">See how many times an employee has been mentioned across cases, and what their role was each time.</p>
    ${lookup.picked ? `
      <div class="kv" style="margin-top:10px"><span class="k">Employee</span><b>${esc(nameOf(lookup.picked))}</b> <span class="muted">· ${esc(roleOf(lookup.picked))}</span>
        <button class="btn sm ghost" style="margin-left:10px" onclick="backToLookup()">change</button></div>
      ${lookup.err?`<div class="banner warn">${esc(lookup.err)}</div>`
        : lookup.result===null?`<div class="card" style="box-shadow:none"><span class="spin"></span></div>`
        : `<div class="banner ${lookup.result.length?'warn':'ok'}"><b>${lookup.result.length}</b> mention(s) in cases you can see.</div>
           ${lookup.result.length?`<table style="margin-top:8px"><thead><tr><th>Case</th><th>Their role</th><th>Status</th><th>Date</th></tr></thead>
           <tbody>${lookup.result.map(r=>`<tr><td><span class="ref">${esc(r.ref)}</span></td><td>${esc(rlabel(r.role_in_case))}</td><td>${pill(r.state)}</td><td>${fmt(r.created_at)}</td></tr>`).join("")}</tbody></table>`:""}`}`
    : `<label>Find an employee</label>
      <input id="lk" type="text" placeholder="Search a name…" value="${esc(lookup.query)}" oninput="onLookupInput(this.value)">
      ${results.map(d=>`<div class="subj-result" data-employee-id="${esc(d.employee_id)}" data-context="lookup" onclick="pickDirectoryResult(this)">${esc(d.name)} — <span class="muted">${esc(d.title||'')}${d.store?' · '+esc(d.store):''}</span></div>`).join("")}`}
  </div>`;
}
function onLookupInput(v){ lookup.query=v; render(); const el=$("lk"); if(el){el.focus();el.setSelectionRange(v.length,v.length);} }
function backToLookup(){ lookup={query:"",picked:null,result:null,err:""}; render(); }
async function pickLookup(id){
  lookup.picked=id; lookup.result=null; lookup.err=""; render();
  const { data, error } = await sb.rpc("mention_lookup",{ p_employee_id:id });
  if(error){ lookup.err = errText(error); } else { lookup.result = data || []; }
  render();
}

// ---------------- STATUS (claim code + my named reports) ----------------
function renderStatus(){
  return `<div class="card">
    <h2 class="section">Check the status of your report</h2>
    <p class="muted">Reported anonymously? Enter your claim code. You'll also get email updates automatically whenever your case changes.</p>
    <label>Claim code</label>
    <div style="display:flex;gap:8px"><input id="cc" type="text" placeholder="e.g. ACDE-4679" value="${esc(statusResult?.tried||'')}"><button class="btn" onclick="doStatusCheck()">Check</button></div>
    ${statusResult ? (statusResult.error ? `<div class="banner err">${esc(statusResult.error)}</div>` : statusResult.found ? renderStatusCard(statusResult) : `<div class="banner warn">No report found for that code.</div>`) : ""}
  </div>
  <div class="card">
    <b style="font-size:14px">Reports you submitted with your name</b>
    ${myReportsLoading?'<p class="muted">Loading your reports…</p>':myReportsError?`<div class="banner err">${esc(myReportsError)} <button class="btn sm sec" onclick="retryMyReports()">Retry</button></div>`:myReports.length?`<table style="margin-top:10px"><thead><tr><th>Ref</th><th>Category</th><th>Status</th><th>Submitted</th></tr></thead>
      <tbody>${myReports.map(c=>`<tr><td><span class="ref">${esc(c.ref)}</span></td><td>${esc(c.category)}</td><td>${pill(c.state)}</td><td>${fmt(c.created_at)}</td></tr>`).join("")}</tbody></table>`
      :'<p class="muted">None found for this email.</p>'}
  </div>`;
}
function loadMyReports(){
  if(myReportsPromise) return myReportsPromise;
  const epoch = sessionEpoch;
  const userId = session?.user?.id;
  myReportsLoading=true; myReportsError="";
  const pending = sb.rpc("my_report_statuses");
  const run = pending.then(({data,error})=>{
    if(epoch !== sessionEpoch || session?.user?.id !== userId) return;
    // Reporters receive only this intentionally narrow status projection.
    myReports = (isHandler||isAdmin||error) ? [] : (data||[]);
    myReportsError = error ? "Report status is temporarily unavailable. Please try again." : "";
    myReportsLoading=false;
    myReportsLoaded=true;
  });
  myReportsPromise = run;
  run.finally(()=>{ if(myReportsPromise === run) myReportsPromise=null; });
  return myReportsPromise;
}
async function removePolicyChipFromElement(el){
  return removePolicyChip(el?.dataset?.case || "", el?.dataset?.policy || "");
}
function retryMyReports(){ myReportsLoaded=false; myReportsLoading=true; render(); }
async function retryEvidenceUploads(){
  if(!evidenceRetry.caseId || !evidenceRetry.files.length || busy) return;
  const epoch = sessionEpoch;
  const caseId = evidenceRetry.caseId;
  const retryFiles = [...evidenceRetry.files];
  busy=true; render();
  const remaining=[];
  try {
    for(const f of retryFiles){
      if(epoch !== sessionEpoch) return;
      if(!(await uploadEvidenceFile(caseId, f))) remaining.push(f);
    }
    if(epoch !== sessionEpoch) return;
    evidenceRetry.files=remaining;
    if(receipt){
      receipt.upNote = remaining.length
        ? `⚠️ ${remaining.length} attachment(s) still failed. Retry again, or contact HR and include reference ${receipt.ref}.`
        : "All attachments uploaded successfully.";
    }
  } finally {
    if(epoch === sessionEpoch){ busy=false; render(); }
  }
}
async function doStatusCheck(){
  const code = $("cc")?.value.trim().toUpperCase(); if(!code) return;
  const epoch = sessionEpoch;
  const { data, error } = await sb.rpc("check_status",{ p_claim_code: code });
  if(epoch !== sessionEpoch) return;
  statusResult = error
    ? {tried:code,found:false,error:"Status lookup is temporarily unavailable. Please try again."}
    : Object.assign({tried:code}, data);
  render();
}
function renderStatusCard(s){
  return `<div class="divider"></div>
    <div class="kv"><span class="k">Reference</span><span class="ref">${esc(s.ref)}</span></div>
    <div class="kv"><span class="k">Status</span>${pill(s.state)}</div>
    <div class="kv"><span class="k">Handled by</span><span>${esc(s.handler||'—')}</span></div>
    <b style="font-size:13px;display:block;margin-top:14px">Messages with HR</b>
    <div class="msgwrap" style="margin:10px 0">${(s.messages||[]).length?s.messages.map(m=>`<div class="msg ${m.sender==='handler'?'handler':m.sender==='email'?'email':'reporter'}"><div class="who">${m.sender==='handler'?'HR':m.sender==='email'?'Email':'You'}${m.sender==='reporter'&&m.via_email?' · via email':''}</div>${linkify(m.body)}</div>`).join(""):'<span class="muted">No messages yet.</span>'}</div>
    <div style="display:flex;gap:8px"><input id="rmsg" type="text" placeholder="Reply to HR (still anonymous)…"><button class="btn sec" onclick="sendReporterReply()">Send</button></div>`;
}
async function sendReporterReply(){
  const v=$("rmsg")?.value.trim(); if(!v)return;
  const epoch = sessionEpoch;
  const claimCode = statusResult?.tried;
  if(!claimCode) return;
  const { error } = await sb.rpc("reporter_reply",{ p_claim_code: claimCode, p_body: v });
  if(epoch !== sessionEpoch) return;
  if(error){ alert(errText(error)); return; }
  await doStatusCheck();
}

// ---------------- helpers / router ----------------
function fmt(ts){ if(!ts) return ""; const d=new Date(ts); return d.toLocaleString(undefined,{month:"short",day:"numeric",hour:"2-digit",minute:"2-digit"}); }
function fmtD(ts){ if(!ts) return "—"; const d=new Date(ts); return d.toLocaleDateString(undefined,{year:"numeric",month:"short",day:"numeric"}); }

// ---------------- EXPORTS (8/28) ----------------
function downloadBlob(blob, name){
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob); a.download = name;
  document.body.appendChild(a); a.click(); a.remove();
  setTimeout(()=>URL.revokeObjectURL(a.href), 5000);
}
// ---- CSV export: the CURRENTLY FILTERED dashboard rows, raw columns + org ----
const csvCell = v => {
  if (v == null) return "";
  let s = typeof v === "object" ? JSON.stringify(v) : String(v);
  // Formula-injection guard (QC 8/31): reporter-entered text opened in Excel
  // must never execute — neutralize leading = + - @ or tab with a quote prefix.
  if (/^[=+\-@\t]/.test(s)) s = "'" + s;
  return /[",\n\r]/.test(s) ? '"' + s.replace(/"/g,'""') + '"' : s;
};
function exportCasesCsv(){
  const cols = DASH_CASE_COLS.split(",");
  const header = [...cols, "region", "district"];
  const rows = lastShown.map(c => [...cols.map(k => csvCell(c[k])), csvCell(caseRegion(c)), csvCell(caseDistrict(c))].join(","));
  // BOM so Excel detects UTF-8; CRLF line endings for the same reason
  const csv = "\uFEFF" + [header.join(","), ...rows].join("\r\n") + "\r\n";
  downloadBlob(new Blob([csv], {type:"text/csv;charset=utf-8"}), `hr-cases-${todayStr()}.csv`);
}
// ---- case .zip export: printable summary + message thread + raw JSON --------
function caseMessagesTxt(){
  const { c, messages, handlerName } = caseExport;
  const who = m => m.sender_type === "handler" ? `HR (${handlerName})`
    : m.sender_type === "email" ? `Email (${m.sender_email || "external"})`
    : (c.anonymous ? "Anonymous reporter" : (c.reporter_display || "Reporter"))
      + (m.via_email ? " · via email (unverified sender)" : "");
  const lines = [
    `Message thread — ${c.ref} (${c.category})`,
    `Exported ${new Date().toLocaleString()} from the People Support Portal`,
    "=".repeat(64), ""];
  if(!messages.length) lines.push("(no messages)");
  for(const m of messages){
    lines.push(`[${new Date(m.created_at).toLocaleString()}] ${who(m)}:`, m.body || "", "");
  }
  return lines.join("\r\n");
}
function caseSummaryHtml(){
  const { c, parties, events, tasks, messages, notes, allegations, interviews, actions, files, handlerName } = caseExport;
  const isReq = c.intake_type === "request";
  const dash = v => (v==null || v==="") ? "—" : esc(v);
  const kv = (k, v) => `<tr><th>${esc(k)}</th><td>${(v==null||v==="")?"—":v}</td></tr>`;
  const sec = (t, body) => `<section><h2>${esc(t)}</h2>${body}</section>`;
  const partyLine = p => p.party_type==="customer" || (!p.subject_id && p.display_name)
    ? `${esc(p.display_name||"Customer")} (customer, ${esc(rlabel(p.role_in_case))})`
    : `${esc(nameOf(p.subject_id))} (${esc(roleOf(p.subject_id)||"")}${p.role_in_case?", "+esc(rlabel(p.role_in_case)):""})`;
  return `<!doctype html><html lang="en"><head><meta charset="utf-8">
<title>${esc(c.ref)} — case summary</title>
<style>
  body{font-family:"Helvetica Neue",Helvetica,Arial,sans-serif;color:#111;margin:32px auto;max-width:820px;line-height:1.5;font-size:14px}
  h1{font-size:22px;margin:0 0 2px} .sub{color:#6b6b6b;font-size:12px;margin-bottom:20px}
  h2{font-size:13px;text-transform:uppercase;letter-spacing:.1em;border-bottom:1px solid #111;padding-bottom:4px;margin:26px 0 10px}
  table{border-collapse:collapse;width:100%} th,td{text-align:left;padding:5px 10px;vertical-align:top;border-bottom:1px solid #eee;font-size:13.5px}
  table.kv th{width:190px;color:#6b6b6b;font-weight:600;font-size:11px;text-transform:uppercase;letter-spacing:.07em}
  table.grid th{color:#6b6b6b;font-size:11px;text-transform:uppercase;letter-spacing:.07em}
  .box{border:1px solid #ddd;background:#fafafa;padding:12px 14px;white-space:pre-wrap}
  .muted{color:#6b6b6b} .pillx{display:inline-block;border:1px solid #111;padding:1px 8px;font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.06em}
  @media print{body{margin:12px}}
</style></head><body>
<h1>${esc(c.ref)} <span class="pillx">${esc(stlabel(c.state))}</span></h1>
<div class="sub">Earthbar &amp; Beaming — People Support Portal · ${isReq?'Request':'Incident case'} summary · exported ${esc(new Date().toLocaleString())}</div>
${sec("Overview", `<table class="kv">
  ${kv("Category", dash(c.category))}
  ${kv("Status", esc(stlabel(c.state)))}
  ${kv("Closure categorization", c.closure_category ? esc(c.closure_category)+(c.closure_ref?` — duplicate of ${esc(c.closure_ref)}`:"") : "—")}
  ${isReq?"":kv(L(c,'riskCol'), dash(caseRisk(c)))}
  ${kv("Location", dash(c.location)+(c.us_state?`, ${esc(c.us_state)}`:""))}
  ${kv("Region / District", esc(caseRegion(c))+" · "+esc(caseDistrict(c)))}
  ${kv("Opened", esc(fmtD(c.created_at)))}
  ${isReq?"":kv("Occurred", c.incident_date?esc(fmtDateOnly(c.incident_date)):"—")}
  ${kv("Closed", c.closed_at?esc(fmtD(c.closed_at)):"—")}
  ${kv(L(c,'reporter'), c.anonymous?"Anonymous":dash(c.reporter_display))}
  ${isReq?"":kv("Relationship", dash(c.reporter_relationship)+(c.reporter_role?` · ${esc(c.reporter_role)}`:""))}
  ${kv(L(c,'handler'), esc(handlerName)+(c.external?" (EXTERNAL)":""))}
  ${kv("Route reason", dash((c.route_reason||"").replace(/_/g," ")))}
  ${kv("Manual entry", c.manual_entry?"Yes":"No")}
  ${isReq?"":kv("Involved", parties.length?parties.map(partyLine).join("<br>"):"—")}
</table>`)}
${sec("Description", `<div class="box">${esc(c.description||"")}</div>`)}
${c.ai_summary?sec("AI review", `<div class="box">${esc(c.ai_summary)}</div>`):""}
${isReq?sec("Accommodation", `<table class="kv">
  ${kv("Outcome", dash(c.accommodation_status))}
  ${kv("Duration", dash(c.accommodation_duration))}
  ${kv("Start", c.accommodation_start?esc(fmtDateOnly(c.accommodation_start)):"—")}
  ${kv("End", c.accommodation_end?esc(fmtDateOnly(c.accommodation_end)):"—")}
</table>`):""}
${isReq?"":sec("Allegations & findings", allegations.length
  ? `<table class="grid"><tr><th>Allegation</th><th>Finding</th></tr>${allegations.map(a=>`<tr><td>${esc(a.allegation)}</td><td>${a.finding?esc(a.finding):'<span class="muted">pending</span>'}</td></tr>`).join("")}</table>`
  : `<p class="muted">None recorded.</p>`)}
${isReq?"":sec("Policies potentially implicated", c.policies?`<div>${esc(c.policies)}</div>`:`<p class="muted">None selected.</p>`)}
${isReq?"":sec("Corrective actions", actions.length
  ? `<table class="grid"><tr><th>Action</th><th>Responsible</th><th>Due</th><th>Completed</th><th>Notes</th></tr>${actions.map(a=>`<tr><td>${dash(a.action_type)}</td><td>${dash(a.responsible)}</td><td>${a.due_date?esc(fmtDateOnly(a.due_date)):"—"}</td><td>${a.completed_date?esc(fmtDateOnly(a.completed_date)):"—"}</td><td>${dash(a.notes)}</td></tr>`).join("")}</table>`
  : `<p class="muted">None recorded.</p>`)}
${isReq?"":sec("Interviews", interviews.length
  ? interviews.map(iv=>`<table class="kv" style="margin-bottom:10px">
      ${kv("Interviewee", dash(iv.interviewee)+(iv.role_in_case?` (${esc(rlabel(iv.role_in_case))})`:""))}
      ${kv("Date / interviewer", (iv.interview_date?esc(fmtDateOnly(iv.interview_date)):"—")+" · "+dash(iv.interviewer)+" · "+dash(iv.status))}
      ${iv.follow_up?kv("Follow-up", esc(iv.follow_up)):""}
    </table>${iv.notes?`<div class="box" style="margin-bottom:16px">${esc(iv.notes)}</div>`:""}`).join("")
  : `<p class="muted">None recorded.</p>`)}
${sec("Follow-up tasks", tasks.length
  ? `<table class="grid"><tr><th>Task</th><th>Status</th><th>Due</th></tr>${tasks.map(t=>`<tr><td>${dash(t.title)}</td><td>${dash(t.status)}</td><td>${t.due_at?esc(fmt(t.due_at)):"—"}</td></tr>`).join("")}</table>`
  : `<p class="muted">No tasks.</p>`)}
${sec("HR notes", notes.length
  ? notes.map(n=>`<div class="box" style="margin-bottom:10px"><div class="muted" style="font-size:11px">${esc(n.author_email||"")} · ${esc(fmt(n.created_at))}</div>${esc(n.body)}</div>`).join("")
  : `<p class="muted">No notes.</p>`)}
${(files||[]).length?sec("Files (received by email)", `<table class="grid"><tr><th>File</th><th>Size</th><th>Source</th></tr>${(files||[]).map(f=>`<tr><td>${esc(f.file_name)}</td><td>${esc(fmtBytes(f.size_bytes))}</td><td>${dash(f.source)}${f.storage_path?"":" — original in the peoplesupport@ mailbox"}</td></tr>`).join("")}</table>`):""}
${sec("Timeline (audit log)", events.length
  ? `<table class="grid"><tr><th>When</th><th>Type</th><th>Note</th></tr>${events.map(e=>`<tr><td style="white-space:nowrap">${esc(fmt(e.at))}</td><td>${dash(e.type)}</td><td>${dash(e.note)}</td></tr>`).join("")}</table>`
  : `<p class="muted">No events.</p>`)}
${sec("Messages", `<p class="muted">${messages.length} message(s) — full thread in <b>messages.txt</b> in this export.</p>`)}
</body></html>`;
}
function exportCaseZip(){
  if(!caseExport || !selected || caseExport.c?.id !== selected){ alert("Open a case first."); return; }
  const { c } = caseExport;
  const zip = makeZip([
    { name: "summary.html", data: caseSummaryHtml() },
    { name: "messages.txt", data: caseMessagesTxt() },
    { name: "case.json",    data: JSON.stringify(caseExport, null, 2) },
  ]);
  const safe = (c.ref || "case").replace(/[^\w.-]+/g, "-");
  downloadBlob(new Blob([zip], {type:"application/zip"}), `${safe}.zip`);
}

function render(){
  renderUserBox(); renderNav();
  const el = $("app");
  if(!session){ el.innerHTML = renderLogin(); return; }
  if((view==="dashboard"||view==="lookup") && !isHandler) view="home";
  if(view==="home"){ el.innerHTML = renderHome(); }
  else if(view==="incident"){ el.innerHTML = renderIncident(); }
  else if(view==="request"){ el.innerHTML = renderRequest(); }
  else if(view==="status"){
    el.innerHTML = renderStatus();
    if(!myReportsLoaded) loadMyReports().then(()=>{ if(view==="status"){ el.innerHTML = renderStatus(); } });
  }
  else if(view==="lookup"){ el.innerHTML = renderLookup(); }
  else if(view==="dashboard"){
    el.innerHTML = `<div class="card"><span class="spin"></span> Loading cases…</div>`;
    if(selected) renderCaseDetailInto(el, selected); else renderDashboardInto(el);
  } else { el.innerHTML = renderHome(); }
}

boot();
