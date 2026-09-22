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
import { DISTRICT_LEADERS, storeOrg } from "./store_org.js";
import { STORE_LOCATIONS } from "./store_locations.js";
import { makeZip } from "./minizip.js";
import { ER_STATEMENT_GUIDE, STATEMENT_TEMPLATE_FILENAME, STATEMENT_TEMPLATE_BUCKET, STATEMENT_TEMPLATE_OBJECT, configureStatementTemplate, clearStatementTemplate, buildBlankBlob, buildFilledBlob } from "./statement_template.js";

const cfg = window.EARTHBAR_CONFIG || {};
// --- SESSION POLICY ---------------------------------------------------------
// Default: sessionStorage + a 24h idle limit. Any signed-in user may opt in to
// an absolute 30-day session on their device. The 30-day deadline never
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

// HR review 2026-09-04 superseded the 7/13 intake decision: these three concerns
// must be available directly to reporters rather than only classified by HR later.
const CATEGORIES = ["Manager conduct","Coworker conduct","Harassment","Discrimination","Retaliation","Workplace safety","Pay / hours dispute","Policy violation","Customer incident","Other"];
const RELATIONSHIPS = ["Employee","Former employee","Customer","Vendor / partner","Other"];
const REQUEST_TYPES = ["Accommodation — Religious","Accommodation — Medical","Accommodation — Other","Other request"];
const RISKS = ["Low","Medium","High"];
const CASE_DETAIL_COLS = "id,ref,category,description,severity,anonymous,handler_id,external,route_reason,state,created_at,closed_at,incident_date,intake_type,location,us_state,reporter_relationship,reporter_role,reporter_display,risk_level,substantiated,substantiated_note,policies,ai_summary,manual_entry,updated_at,accommodation_status,accommodation_start,accommodation_end,accommodation_duration,closure_category,closure_ref,requester_id";
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
  "Code of Conduct","Complaint Procedure","Reasonable Accommodations","Fraternization","Meal Period and Rest Break Policy","Attendance",
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
// Dropdown values start with the workbook's "Lists" tab and include HR-requested additions (Flora, 2026-09-21).
const WC_MARKETS = ["Berkeley","San Francisco","San Diego / Carlsbad","New York City","Seattle","Washington DC","Mamaroneck NY","Armonk NY","Darien CT","Fairfield CT","Collegeville PA","Boston MA","Dallas TX","Los Angeles CA"];
const WC_STATES = ["CA","NY","WA","DC","CT","PA","MA","FL","GA","MD","MI","NJ","TX","VA"];
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
const LEGAL_STATUSES = ["Received","Documentation Sent","Negotiating","Litigation","Settlement Reached"];   // Settlement Reached added T137 (9/15 Ops/People meeting)
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
// T135 (9/15): the period list only reached P7, so nothing opened after Jul 12
// could ever match a period — extended through P13 using the same 4-week
// arithmetic as the P5–P7 anchors. All 13 date ranges verified against the
// canonical KPI Scorecard Calendar tab on 2026-09-15 (exact match — do not edit).
const FISCAL_PERIODS = {
  P1:{ from:"2025-12-29", to:"2026-01-25", label:"P1 · Dec 29–Jan 25" },
  P2:{ from:"2026-01-26", to:"2026-02-22", label:"P2 · Jan 26–Feb 22" },
  P3:{ from:"2026-02-23", to:"2026-03-22", label:"P3 · Feb 23–Mar 22" },
  P4:{ from:"2026-03-23", to:"2026-04-19", label:"P4 · Mar 23–Apr 19" },
  P5:{ from:"2026-04-20", to:"2026-05-17", label:"P5 · Apr 20–May 17" },
  P6:{ from:"2026-05-18", to:"2026-06-14", label:"P6 · May 18–Jun 14" },
  P7:{ from:"2026-06-15", to:"2026-07-12", label:"P7 · Jun 15–Jul 12" },
  P8:{ from:"2026-07-13", to:"2026-08-09", label:"P8 · Jul 13–Aug 9" },
  P9:{ from:"2026-08-10", to:"2026-09-06", label:"P9 · Aug 10–Sep 6" },
  P10:{ from:"2026-09-07", to:"2026-10-04", label:"P10 · Sep 7–Oct 4" },
  P11:{ from:"2026-10-05", to:"2026-11-01", label:"P11 · Oct 5–Nov 1" },
  P12:{ from:"2026-11-02", to:"2026-11-29", label:"P12 · Nov 2–Nov 29" },
  P13:{ from:"2026-11-30", to:"2026-12-27", label:"P13 · Nov 30–Dec 27" },
};
const CUSTOM_PERIOD = "__custom";

// ---- state ----
let session = null, me = null, isHandler = false, isAdmin = false, signedOutReason = "", trustedDeviceNotice = "";
// A guided real-case exercise, not a different identity or authorization role.
let employeeTest = false, employeeTestReceipt = null;
let statusLookupGeneration = 0;
const EMPLOYEE_TEST_PREFIX = "[TEST ONLY — employee portal exercise]";
let dirList = [], dirMap = {}, storeList = [], stateMap = {}, statesList = [], dirLoaded = false;
let view = "home", selected = null, busy = false, errorMsg = "";
let auth = { email:"", sent:false, err:"", remember:false };
let form = blankIncident();
let qform = { location:"", body:"", email:"", rtype:REQUEST_TYPES[0] };
let dashView = "cases";
let receipt = null, statusResult = null, myReports = [], myReportsError = "", myReportsLoading = true, myReportsLoaded = false;
let myReportsPromise = null;
const blankDashboardFilters = () => ({ q:"", risk:"", cat:"", state:"", handler:"", period:"", pfrom:"", pto:"", acc:"", dur:"", us:"", loc:"", leader:"", quick:"", mine:"" });
let filters = blankDashboardFilters();
let dashboardData = [];
// 8/18 call: state changes need a second "save" click before anything is
// recorded — first click arms the move, second click confirms it.
let pendingAdvance = null;   // { id, to } while a state move awaits confirmation
let showFilters = false, showGuide = false, showReassign = false;
let hrTeam = [];
let showManual = false, manual = blankIncident(true);
let wcSelected = null;      // null = list; "new" = create form; else wc_cases.id
let wcFilters = { q:"", status:"", state:"", asg:"", quick:"" };
let wcData = [];
// WC claim documents. Staged File objects live here (not in the DOM) so the
// scoped #wc-docs-box repaints never lose a selection; seq guards stale lists.
let wcDocs = { caseId:null, list:[], loaded:false, listError:"", files:[], status:"", error:"", busy:false, retry:false, seq:0 };
let lgSelected = null;      // null = list; "new" = create form; else legal_cases.id
let lgFilters = { q:"", state:"", risk:"", status:"", type:"", quick:"active" };   // Active by default (spec)
let legalData = [];
let lgEditing = false;
let legalDetail = { notes:[], files:[], links:[], linkedCases:{}, linkedFiles:{}, errors:[] };
let legalComposer = { caseId:null, note:"", files:[], status:"", error:"", noteError:"", retry:false };
// T137 linked-cases picker. Query is bound to state with a silent oninput so a
// full render() never loses typed text; results paint into their own container.
let legalLinkPicker = { caseId:null, query:"", results:[], linked:[], busy:false, err:"", seq:0 };
let legalLinkTimer = null;
let legalBusy = { note:false, upload:false };
let legalPreview = { open:false, caseId:null, storedName:"", name:"", url:"", kind:"" };
let legalPreviewGeneration = 0;
let legalPreviewRestoreName = "";
let attachmentPreview = { open:false, name:"", url:"", text:"", kind:"", note:"", download:null, restoreId:"" };
let attachmentPreviewGeneration = 0;
let attachmentPreviewObjectUrl = "";
let messageThread = { key:"", caseId:null, claimCode:null, messages:[], body:"", files:[], busy:false, error:"", status:"", requestId:null, prepared:null, uploaded:[] };
let messageThreadGeneration = 0;
let closeModal = { open:false, caseId:null, kind:"incident", sub:null, status:"", note:"", cat:"", ref:"" };
let lastShown = [];        // rows currently visible on the cases/requests dashboard (feeds Export CSV)
let caseExport = null;     // everything fetched for the open case detail (feeds Export case .zip)
let caseExportInProgress = false, caseExportGeneration = 0;
let lookup = { query:"", picked:null, result:null, err:"" };
let evidence = { list:[], err:"" };
let partySearchResults = [], partySearchSeq = 0, partySearchTimer = null, partySearchError = "";
let partyEditor = { open:false, caseId:null, expectedUpdatedAt:null, parties:[], query:"", role:"subject", busy:false, err:"" };
let evidenceRetry = { caseId:null, files:[] };
let activeUserId = null, sessionEpoch = 0;
let interviewSavePromises = new Map();
let interviewDrafts = new Map();
let statementTemplatePromise = null;
const MEDICAL_FUNCTION = "medical-documents";
const MEDICAL_FILE_RULES = { maxBytes:10*1024*1024, mimeByExtension:{
  pdf:["application/pdf"], png:["image/png"], jpg:["image/jpeg"], jpeg:["image/jpeg"],
  docx:["application/vnd.openxmlformats-officedocument.wordprocessingml.document"]
} };
function takeMedicalInviteToken(){
  const raw=location.hash.startsWith("#")?location.hash.slice(1):"";
  if(!raw)return "";
  const params=new URLSearchParams(raw);
  const token=params.get("medical-return")||params.get("medical_return")||params.get("medicalReturn")||"";
  if(!token)return "";
  history.replaceState(history.state,"",location.pathname+location.search);
  return token;
}
let medicalInviteToken=takeMedicalInviteToken();
let medicalInvite={status:"",error:"",request:null,documents:[],files:[],kind:"accommodation",label:"",busy:false,generation:0};
let medicalPanel={caseId:null,status:"idle",error:"",capabilities:null,documents:[],returnRequests:[],files:[],kind:"accommodation",label:"",busy:false,mfa:{mode:"",factorId:"",qr:"",secret:"",error:"",busy:false},invite:{email:"",kind:"accommodation",dueDays:"14",dueAt:"",message:"",formType:"medical",status:"",error:"",busy:false},editingDueDate:null,audit:[],auditStatus:"idle",auditError:"",auditGroup:"all",auditCursor:null,auditGeneration:0,retention:[],generation:0};

function blankMedicalPanel(caseId=null){return {caseId,status:"idle",error:"",capabilities:null,documents:[],returnRequests:[],files:[],kind:"accommodation",label:"",busy:false,mfa:{mode:"",factorId:"",qr:"",secret:"",error:"",busy:false},invite:{email:"",kind:"accommodation",dueDays:"14",dueAt:"",message:"",formType:"medical",status:"",error:"",busy:false},editingDueDate:null,audit:[],auditStatus:"idle",auditError:"",auditGroup:"all",auditCursor:null,auditGeneration:medicalPanel.auditGeneration+1,retention:[],generation:medicalPanel.generation+1};}
function medicalCurrent(caseId,generation,epoch,userId){return selected===caseId&&medicalPanel.caseId===caseId&&medicalPanel.generation===generation&&sessionEpoch===epoch&&session?.user?.id===userId;}
function medicalError(result){return result?.error||result?.data?.error||null;}
async function medicalAction(body){
  const result=await sb.functions.invoke(MEDICAL_FUNCTION,{body});
  let error=medicalError(result);
  if(result?.error?.context&&typeof result.error.context.json==="function"){
    try{const payload=await result.error.context.clone().json();error=payload?.error||error;}catch{}
  }
  const data=!error&&["commit_upload","commit_return_upload"].includes(body?.action)
    ? (result.data?.document||result.data) : result.data;
  return {data:error?null:data,error};
}

function verifiedEmail(){ return (session?.user?.email || "").trim().toLowerCase(); }
function canUseDirectorySearch(){ return !!session; }
function resetSessionState(preserveMedicalInvite=false){
  employeeTest = false; employeeTestReceipt = null;
  statementTemplatePromise=null; clearStatementTemplate();
  setLegalPreviewBackgroundInert(false);
  closeAttachmentPreview(false);
  clearTimeout(idleExpiryTimer); idleExpiryTimer = null;
  clearTimeout(trustedExpiryTimer); trustedExpiryTimer = null;
  trustedSessionDeadline = 0;
  clearAllManualDrafts();
  sessionEpoch += 1;
  clearTimeout(partySearchTimer); partySearchTimer = null; partySearchSeq += 1;
  clearTimeout(draftTimer); draftTimer = null;
  me = null; isHandler = false; isAdmin = false; trustedDeviceNotice = "";
  auth = { email:"", sent:false, err:"", remember:false };
  dirList = []; dirMap = {}; storeList = []; stateMap = {}; statesList = []; hrTeam = []; dirLoaded = false;
  view = "home"; selected = null; busy = false; errorMsg = "";
  form = blankIncident();
  qform = { location:"", body:"", email:"", rtype:REQUEST_TYPES[0] };
  dashView = "cases"; receipt = null; statusResult = null;
  myReports = []; myReportsError = ""; myReportsLoading = true; myReportsLoaded = false; myReportsPromise = null;
  filters = blankDashboardFilters(); dashboardData = []; dashSort = { key:"", dir:1 };
  for (const key of Object.keys(employeeLookups)) employeeLookups[key].query = "";
  pendingAdvance = null; showFilters = false; showGuide = false; showReassign = false;
  showManual = false; manual = blankIncident(true); manualDraftAt = null; draftPending = false; draftSaveFailed = false;
  wcSelected = null; wcFilters = { q:"", status:"", state:"", asg:"", quick:"" }; wcData = []; wcSort = { key:"", dir:1 };
  lgSelected = null; lgFilters = { q:"", state:"", risk:"", status:"", type:"", quick:"active" }; legalData = []; lgSort = { key:"", dir:1 };
  lgEditing = false; legalDetail = { notes:[], files:[], errors:[] };
  legalComposer = { caseId:null, note:"", files:[], status:"", error:"", noteError:"", retry:false }; legalBusy = { note:false, upload:false };
  legalPreview = { open:false, caseId:null, storedName:"", name:"", url:"", kind:"" }; legalPreviewGeneration += 1;
  messageThread = blankMessageThread(); messageThreadGeneration += 1;
  closeModal = { open:false, caseId:null, kind:"incident", sub:null, status:"", note:"", cat:"", ref:"" };
  lastShown = []; caseExport = null; caseAllegs = [];
  cdRequester = { caseId:null, err:"", busy:false };
  caseExportInProgress = false; caseExportGeneration += 1;
  lookup = { query:"", picked:null, result:null, err:"" };
  evidence = { list:[], err:"" }; evidenceRetry = { caseId:null, files:[] };
  partySearchResults = []; partySearchError = "";
  partyEditor = { open:false, caseId:null, expectedUpdatedAt:null, parties:[], query:"", role:"subject", busy:false, err:"" };
  interviewSavePromises.clear();
  interviewDrafts.clear();
  medicalPanel=blankMedicalPanel();
  if(!preserveMedicalInvite){
    medicalInviteToken="";
    medicalInvite={status:"",error:"",request:null,documents:[],files:[],kind:"accommodation",label:"",busy:false,generation:medicalInvite.generation+1};
  }
}

function todayStr(){ const d=new Date(); return d.getFullYear()+'-'+String(d.getMonth()+1).padStart(2,'0')+'-'+String(d.getDate()).padStart(2,'0'); }
function blankIncident(isManual = false){
  return { anonymous:false, location:"", usState:"", relationship:"Employee", role:"",
    category:CATEGORIES[0], parties:[], pQuery:"", pType:"employee", pName:"",
    pRoles:["subject"], description:"", email:"", phone:"", files:[], manual:isManual,
    incidentDate: todayStr(), kind:"case", requesterId:"", requesterName:"",
    requesterAutoEmail:"", requesterAutoLocation:"" };
}
const OTHER_LOCATION = "Other / not store-specific";
const REFERENCE_STATE_MAP = Object.fromEntries(STORE_LOCATIONS.map(location => [location.name, location.state]));
function locationPicker(id, selected, inputHandler, optional = false){
  const listId = `${id}-options`;
  const helpId = `${id}-help`;
  return `<input id="${id}" class="location-search" type="search" list="${listId}"
    value="${esc(selected)}" placeholder="Search by city or location name…" autocomplete="off"
    inputmode="search" autocapitalize="words" spellcheck="false" aria-describedby="${helpId}"
    oninput="${inputHandler}(this.value)">
    <datalist id="${listId}">
      ${storeList.map(name=>`<option value="${esc(name)}" label="${esc(stateMap[name]||'')}"></option>`).join("")}
      <option value="${OTHER_LOCATION}"></option>
    </datalist>
    <p id="${helpId}" class="note-sm location-search-help">Start typing to search by city or location name${optional?", or leave blank if it isn't store-specific":""}.</p>`;
}
function canonicalLocation(value, required = false){
  const raw = String(value || "").trim();
  if (!raw) return required ? null : "";
  if (raw.toLowerCase() === OTHER_LOCATION.toLowerCase()) return OTHER_LOCATION;
  return storeList.find(name => name.toLowerCase() === raw.toLowerCase()) || null;
}
const locationError = required => required
  ? `Please choose a location from the search results, or select “${OTHER_LOCATION}”.`
  : "Please choose a valid location from the search results or clear the field.";

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
// District leader comes from the daily Store Directory snapshot embedded in
// store_org.js. Unmatched or non-store locations bucket under "Other".
const caseDistrictLeader = c => storeOrg(c.location)?.districtLeader || "Other";
// Monique is listed under her legal name in the Store Directory. Keep the
// source value for matching while showing the name Operations uses day to day.
const districtLeaderLabel = value => value === "Latoya Martin" ? "Monique (Latoya Martin)" : value;
const caseOpenedInPeriod = (c, key) => {
  const opened = new Date(c.created_at).getTime();
  if (key === CUSTOM_PERIOD) {   // T135: custom date range (either bound optional)
    if (!filters.pfrom && !filters.pto) return true;
    const from = filters.pfrom ? new Date(filters.pfrom + "T00:00:00").getTime() : -Infinity;
    const to = filters.pto ? new Date(filters.pto + "T23:59:59.999").getTime() : Infinity;
    return opened >= from && opened <= to;
  }
  const p = FISCAL_PERIODS[key];
  if (!p) return true;
  return opened >= new Date(p.from + "T00:00:00").getTime()
    && opened <= new Date(p.to + "T23:59:59.999").getTime();
};
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

// ---------------- shared employee lookup (T136) ----------------
// Two tiers of sharing. The MATCHER (employeeMatches) is shared by every
// directory search: this component, the case party builder, the party
// editor, and the Employee mention lookup view. The COMPONENT
// (registerEmployeeLookup + employeeLookupHtml) is used only where a single
// person is picked: the manual-request requester, the legal editor
// complainant, the medical return-request recipient, and the case-detail
// set-requester control — the party surfaces keep their own multi-select
// UI and share just the matcher.
// Accent-insensitive, so "Jose" finds "José". Results show
// "Name (EID)"; EID = directory.employee_id, location = directory.store.
// Each instance repaints ONLY its own container — a full render() mid-form
// wipes typed input (bug 9/1), so hosts pass repaint callbacks instead.
const normSearch = s => { try { return String(s ?? "").normalize("NFD").replace(/[̀-ͯ]/g, "").toLowerCase(); } catch { return String(s ?? "").toLowerCase(); } };
function employeeMatches(query, limit = 8){
  const q = normSearch(String(query || "").trim());
  if (q.length < 2) return [];
  return dirList.filter(d => normSearch(d.name).includes(q)
    || normSearch(d.title).includes(q)
    || normSearch(d.employee_id).startsWith(q)
    || normSearch(d.employee_number).startsWith(q)
    || (Array.isArray(d.search_names) && d.search_names.some(n=>normSearch(n).includes(q)))).slice(0, limit);
}
const employeeLookups = {};   // instance id -> { query, activeIndex, placeholder, getSelected, onPick, onClear }
// Hosts re-register on every render so callbacks close over current state;
// the typed query and keyboard position survive the re-registration. If an
// async host repaint replaces the focused combobox, restore its focus after
// the new DOM is installed instead of dropping the user back to the page.
function registerEmployeeLookup(id, opts){
  const previous = employeeLookups[id] || {};
  const focused = document.activeElement?.id === `el-in-${id}`;
  employeeLookups[id] = Object.assign({ query:"", activeIndex:-1, restoreFocus:false }, previous, opts);
  const context = previous.focusContext;
  if (context && (context.epoch !== sessionEpoch || context.view !== view || context.caseId !== selected)){
    employeeLookups[id].restoreFocus = false;
  }
  if (focused){
    employeeLookups[id].restoreFocus = true;
    employeeLookups[id].focusContext = { epoch:sessionEpoch, view, caseId:selected };
  }
  return id;
}
function employeeLookupResultsHtml(id){
  const inst = employeeLookups[id]; if (!inst) return "";
  const results = employeeMatches(inst.query);
  if (inst.activeIndex >= results.length) inst.activeIndex = results.length - 1;
  const queried = inst.query.trim().length >= 2;
  const note = queried && !results.length
    ? `<p class="note-sm" role="status" aria-live="polite" style="margin-top:6px">${dirLoaded ? "No matching employee in the directory." : "Loading directory…"}</p>` : "";
  return `${note}<div id="el-list-${id}" role="listbox" aria-label="Employee search results">
    ${results.map((d,index)=>`<div id="el-opt-${id}-${index}" class="subj-result" role="option" aria-selected="${index === inst.activeIndex}" data-el-instance="${esc(id)}" data-employee-id="${esc(d.employee_id)}" onclick="elPickResult(this)">${esc(d.name)} <span class="muted">(${esc(d.employee_id)})</span> — <span class="muted">${esc(d.title||'')}${d.store?' · '+esc(d.store):''}</span></div>`).join("")}
  </div>`;
}
function elQueueFocus(id){
  const scheduled = employeeLookups[id]; if (!scheduled) return;
  const epoch = sessionEpoch, scheduledView = view, scheduledCase = selected;
  const activeAtQueue = document.activeElement;
  const pickerHadFocus = !activeAtQueue || activeAtQueue === document.body
    || activeAtQueue.id === `el-in-${id}` || activeAtQueue.id === `el-clear-${id}`;
  if (!pickerHadFocus){ scheduled.restoreFocus = false; return; }
  const request = (scheduled.focusRequest || 0) + 1;
  scheduled.focusRequest = request;
  setTimeout(() => {
    const inst = employeeLookups[id];
    if (inst !== scheduled || inst.focusRequest !== request || !inst.restoreFocus
        || sessionEpoch !== epoch || view !== scheduledView || selected !== scheduledCase) return;
    const active = document.activeElement;
    if (active && active !== document.body && active !== activeAtQueue
        && active.id !== `el-in-${id}` && active.id !== `el-clear-${id}`){
      inst.restoreFocus = false; return;
    }
    const target = inst.getSelected?.() ? $(`el-clear-${id}`) : $(`el-in-${id}`);
    if (!target) return;
    inst.restoreFocus = false; target.focus();
    if (target.setSelectionRange) target.setSelectionRange(target.value.length, target.value.length);
  }, 0);
}
function employeeLookupHtml(id){
  const inst = employeeLookups[id];
  if (!inst) return "";
  const sel = inst.getSelected?.();
  if (sel){
    const d = dirMap[sel.id];
    const label = `${d?.name || sel.name || sel.id} (${sel.id})`;
    if (inst.restoreFocus) elQueueFocus(id);
    return `<div id="el-${id}" class="emp-lookup"><span class="chip">${esc(label)}${d?.store?` · <i>${esc(d.store)}</i>`:""} <button id="el-clear-${id}" type="button" class="el-clear" onclick="elClear('${id}')" aria-label="Clear selected employee">×</button></span></div>`;
  }
  const results = employeeMatches(inst.query);
  if (inst.activeIndex >= results.length) inst.activeIndex = results.length - 1;
  if (inst.restoreFocus) elQueueFocus(id);
  const active = inst.activeIndex >= 0 && results[inst.activeIndex] ? ` aria-activedescendant="el-opt-${id}-${inst.activeIndex}"` : "";
  return `<div id="el-${id}" class="emp-lookup">
    <input id="el-in-${id}" type="text" role="combobox" aria-label="${esc(inst.ariaLabel || "Search employees")}" aria-autocomplete="list" aria-controls="el-list-${id}" aria-expanded="${inst.query.trim().length >= 2}"${active} placeholder="${esc(inst.placeholder || "Search name, title, or employee ID…")}" value="${esc(inst.query)}" autocomplete="off" oninput="elInput('${id}',this.value)" onkeydown="elKeyDown('${id}',event)">
    <div id="el-results-${id}">${employeeLookupResultsHtml(id)}</div>
  </div>`;
}
function elRepaint(id){ const el = $(`el-${id}`); if (el) el.outerHTML = employeeLookupHtml(id); }
function elRefreshResults(id){
  const inst = employeeLookups[id], input = $(`el-in-${id}`), results = $(`el-results-${id}`);
  if (!inst || !input || !results) return;
  results.innerHTML = employeeLookupResultsHtml(id);
  const matches = employeeMatches(inst.query), active = inst.activeIndex >= 0 && matches[inst.activeIndex];
  input.setAttribute("aria-expanded", String(inst.query.trim().length >= 2));
  if (active) input.setAttribute("aria-activedescendant", `el-opt-${id}-${inst.activeIndex}`);
  else input.removeAttribute("aria-activedescendant");
}
function elInput(id, v){
  const inst = employeeLookups[id]; if (!inst) return;
  inst.query = v; inst.activeIndex = -1;
  const input = $(`el-in-${id}`); if (input && input.value !== v) input.value = v;
  elRefreshResults(id);
}
function elKeyDown(id, event){
  const inst = employeeLookups[id]; if (!inst) return;
  const results = employeeMatches(inst.query);
  if (event.key === "Escape"){
    if (!inst.query && !results.length) return;
    event.preventDefault(); inst.query = ""; inst.activeIndex = -1;
    const input = $(`el-in-${id}`); if (input) input.value = "";
    elRefreshResults(id); return;
  }
  if (!results.length || !["ArrowDown","ArrowUp","Enter"].includes(event.key)) return;
  if (event.key === "Enter"){
    if (inst.activeIndex < 0) return;
    event.preventDefault(); elPick(id, results[inst.activeIndex].employee_id); return;
  }
  event.preventDefault();
  if (event.key === "ArrowDown") inst.activeIndex = Math.min(results.length - 1, inst.activeIndex + 1);
  else inst.activeIndex = inst.activeIndex < 0 ? results.length - 1 : Math.max(0, inst.activeIndex - 1);
  elRefreshResults(id);
  $(`el-opt-${id}-${inst.activeIndex}`)?.scrollIntoView({ block:"nearest" });
}
function elPick(id, empId){
  const inst = employeeLookups[id];
  if (!inst || !empId || !dirMap[empId]) return;
  inst.query = ""; inst.activeIndex = -1; inst.restoreFocus = true;
  inst.focusContext = { epoch:sessionEpoch, view, caseId:selected };
  if (inst.onPick) inst.onPick(dirMap[empId]); else elRepaint(id);
  elQueueFocus(id);
}
function elPickResult(el){
  const id = el?.dataset?.elInstance || "", empId = el?.dataset?.employeeId || "";
  elPick(id, empId);
}
function elClear(id){
  const inst = employeeLookups[id]; if (!inst) return;
  inst.query = ""; inst.activeIndex = -1; inst.restoreFocus = true;
  inst.focusContext = { epoch:sessionEpoch, view, caseId:selected };
  if (inst.onClear) inst.onClear(); else elRepaint(id);
  elQueueFocus(id);
}

Object.assign(window, { go, sendOtp, verifyOtp, signOut,
  setRememberDevice,
  setF, setIncidentLocation, addParty, rmParty, onPartyInput, pickPartyEmp, pickDirectoryResult, toggleRole, mToggleRole, submitIncident, submitRequest,
  startEmployeeTest, endEmployeeTest, openEmployeeTestStatus,
  setDashView, addNote, toggleGuide, saveAccommodation, toggleReassign, doReassign, setCloseStatus,
  cancelAdvance,
  addAllegationUI, setFindingUI, removeAllegationUI, addPolicyChip, removePolicyChipFromElement,
  saveInterviewUI, addInterviewUI, deleteInterviewUI, saveActionUI, addActionUI, deleteActionUI,
  syncInterviewDraft, addInterviewPair, removeInterviewPair, moveInterviewPair, downloadBlankStatement, downloadFilledStatement,
  logInterviewContactAttempt, removeInterviewContactAttempt, exportInterviewPdf, setPeriodFilter,
  toggleTask, evDownload, evPreview, caseFileDownload, caseFilePreview,
  openCase, closeCase, doAdvance, sendHandlerMsg, doStatusCheck, sendReporterReply, openNamedReportMessages,
  setFilter, applyFilters, toggleFilters, clearDashboardFilter, clearDashboardFilters, setDashboardQuickFilter, setDashSort, toggleMyWork, toggleManual, setM, setManualLocation, mAddParty, mRmParty, mOnPartyInput, mPickPartyEmp, submitManual, submitManualRequest, discardManualDraft,
  elInput, elKeyDown, elPickResult, elClear, toggleCdRequester,
  wcOpen, wcClose, wcSave, wcApplyFilters, setWcQuickFilter, clearWcFilter, clearWcFilters, setWcSort, setLegalSort,
  wcSetFiles, wcUploadDocuments, wcDownloadDocument,
  lgOpen, lgClose, lgEdit, lgCancelEdit, lgSave, lgApplyFilters, setLegalQuickFilter, clearLegalFilter, clearLegalFilters,
  lgSetNoteDraft, lgSetFiles, lgAddNote, lgUploadDocuments, lgPreviewDocument, lgDownloadDocument, lgClosePreview,
  lgLinkSearchInput, lgLinkCase, lgUnlinkCase, lgLinkedEvidencePreview, lgLinkedEvidenceDownload,
  lgLinkedCaseFilePreview, lgLinkedCaseFileDownload, lgLinkedMessagePreview, lgLinkedMessageDownload,
  openCloseModal, cancelCloseModal, setCloseSub, setCloseCat, confirmClose,
  exportCasesCsv, exportCaseZip, assertCaseZipBudget,
  saveRisk, savePolicies, uploadCaseEvidence,
  togglePartyEditor, setPartyEditRole, onPartyEditInput, pickPartyEditEmployee, removePartyEdit, savePartyEdit,
  onLookupInput, pickLookup, backToLookup, retryMyReports, retryEvidenceUploads,
  setMessageBody, setMessageFiles, sendMessageWithAttachments, previewMessageAttachment, downloadMessageAttachment, closeAttachmentPreview, downloadOpenAttachment,
  loadMedicalPanel, startMedicalMfa, verifyMedicalMfa, handleMedicalQrError, setMedicalFiles, uploadMedicalFiles, previewMedicalDocument, downloadMedicalDocument,
  setMedicalInviteField, createMedicalReturnRequest, resendMedicalReturnRequest, toggleMedicalLegalHold, loadMedicalAudit, setMedicalAuditGroup, previewMedicalRetention, enqueueMedicalRetention,
  sendMedicalReturnForm, revokeMedicalReturnRequest, startMedicalDueDateEdit, setMedicalDueDateValue, cancelMedicalDueDateEdit, saveMedicalDueDate,
  setMedicalReturnFiles, submitMedicalReturnFiles });

// ---------------- AUTH / BOOTSTRAP ----------------
async function boot(){
  for (const eventName of USER_ACTIVITY_EVENTS) {
    document.addEventListener(eventName, recordUserActivity, true);
  }
  document.addEventListener("keydown", handleLegalPreviewKeydown, true);
  document.addEventListener("keydown", handleAttachmentPreviewKeydown, true);
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
      resetSessionState(!activeUserId && !!nextUserId && !!medicalInviteToken);
      activeUserId = nextUserId;
      if(nextUserId) touchLastSeen();
    }
    session = s;
    if(s){
      const expected = nextUserId;
      loadContext().then(()=>{ if(session?.user?.id === expected && !applyInitialRoute()) render(); });
    } else {
      clearAllAuthStorage();
      // Keep the deep link armed so signing back in lands on the same page.
      initialRoutePending = location.hash.startsWith("#/");
      render();
    }
  });
  window.addEventListener("hashchange", () => {
    if (routeApplying || !session || medicalInviteToken) return;
    if (!location.hash.startsWith("#/")) return;
    if (location.hash === "#" + currentRoute()) return;
    applyRoute();
  });
  if (session) { touchLastSeen(); await loadContext(); }
  if (!session || !applyInitialRoute()) render();
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
    let result = await sb.from("directory").select("employee_id,name,email,title,store,manager_id,employee_number,search_names");
    // Permit an independently staged frontend release before the additive migration.
    if(result.error && ["42703","PGRST204"].includes(result.error.code)) result = await sb.from("directory").select("employee_id,name,email,title,store,manager_id");
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
  if(!isHandler){ employeeTest=false; employeeTestReceipt=null; }
  dirList = dir;
  dirMap = Object.fromEntries(dirList.map(d => [d.employee_id, d]));
  dirLoaded = nextIsHandler;   // handlers now have the directory; lookups can say "no match" honestly
  const databaseStateMap = Object.fromEntries((ss||[])
    .filter(row => row.store && row.us_state)
    .map(row => [row.store, row.us_state]));
  stateMap = { ...REFERENCE_STATE_MAP, ...databaseStateMap };
  storeList = [...new Set([
    ...STORE_LOCATIONS.map(location => location.name),
    ...(ss||[]).map(row => row.store).filter(Boolean),
  ])].sort((a, b) => a.localeCompare(b));
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
  if(!/^\d{6}$/.test(token)){ auth.err = "Enter the 6-digit code from your email."; render(); return; }
  const rememberRequested = !!auth.remember;
  busy = true; render();
  const { data, error } = await sb.auth.verifyOtp({ email: auth.email, token, type: "email" });
  if(error){ busy = false; auth.err = "That code didn't work. Check the code and try again."; render(); return; }
  if (rememberRequested) {
    if (!activateTrustedDevice(data?.session || session)) {
      trustedDeviceNotice = "This browser blocked persistent storage, so this sign-in will end when the browser closes.";
    } else {
      trustedDeviceNotice = "This device will keep you logged in for up to 30 days. Sign out sooner if anyone else may use it.";
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
  if (isHandler) t.push({id:"dashboard",label:"HR Dashboard"},{id:"lookup",label:"Employee Lookup"},{id:"employee-test",label:"Employee test"});
  return t;
}
function go(v){
  if(employeeTest && busy) return;
  if(v==="employee-test" && !isHandler) v="home";
  if(employeeTest && !["home","incident","status"].includes(v)){
    if((form.description.trim() || form.files?.length || form.parties.length) && !confirm("Leave this test draft? It has not been submitted.")) return;
    employeeTest=false; form=blankIncident(); form.email=verifiedEmail();
  }
  statusLookupGeneration += 1; messageThreadGeneration += 1;
  closeAttachmentPreview(false);
  if ((v==="dashboard"||v==="lookup") && !isHandler) v="home";
  if (showManual){ syncManualFields(); flushManualDraft(true); }   // nav closes the form — persist the debounce tail first
  view=v; clearSelectedCaseState(); receipt=null; errorMsg=""; showManual=false;
  if(v!=="dashboard"){ setLegalPreviewBackgroundInert(false); legalBusy={note:false,upload:false}; legalPreview=blankLegalPreview(); legalPreviewGeneration+=1; }
  if(v==="status"){ myReportsError=""; myReportsLoading=true; myReportsLoaded=false; }
  render(); syncRoute();
}

// ---------------- HASH ROUTES ----------------
// Deep links so a refresh restores the page being viewed (Eitan 2026-09-16):
// #/home|status|incident|request|lookup, #/dashboard/<tab>,
// #/dashboard/<tab>/case/<uuid>, #/dashboard/wc/<uuid>, #/dashboard/legal/<uuid>.
// Hash-based on purpose — works on GitHub Pages today and any static host
// later, no server rewrites. The bare "#key=value" form stays reserved for
// the medical-return invite token (takeMedicalInviteToken strips it at load;
// routes always start with "#/"). Navigation functions call syncRoute(),
// which collapses same-tick updates into one hash write; hashchange (back /
// forward / hand-edited URL) re-applies through the SAME nav functions so
// draft-flush and state-reset invariants hold. New-entry forms (wc/legal
// "new") deliberately have no route — a refresh must not resurrect a blank
// form over typed, unsaved fields.
// Loose on purpose: ids only ever reach parameterized .eq("id",…) queries and
// esc()'d DOM; a junk id just renders that view's own not-found state.
const ROUTE_ID = /^[A-Za-z0-9_-]{1,64}$/;
const ROUTE_DASH_VIEWS = ["cases","requests","closed","wc","legal"];
let routeApplying = false, routeSyncQueued = false;
let initialRoutePending = location.hash.startsWith("#/");
function currentRoute(){
  if (view === "dashboard"){
    if (selected) return `/dashboard/${dashView}/case/${selected}`;
    if (dashView === "wc" && wcSelected && wcSelected !== "new") return `/dashboard/wc/${wcSelected}`;
    if (dashView === "legal" && lgSelected && lgSelected !== "new") return `/dashboard/legal/${lgSelected}`;
    return `/dashboard/${dashView}`;
  }
  return "/" + view;
}
function syncRoute(){
  if (routeApplying || routeSyncQueued || !session || medicalInviteToken) return;
  routeSyncQueued = true;
  queueMicrotask(() => {
    routeSyncQueued = false;
    if (routeApplying || !session || medicalInviteToken) return;
    const target = "#" + currentRoute();
    if (location.hash !== target) location.hash = target;
  });
}
function applyRoute(){
  if (!session || medicalInviteToken || !location.hash.startsWith("#/")) return false;
  const parts = location.hash.slice(2).split("/").filter(Boolean);
  routeApplying = true;
  try {
    const head = parts[0] || "home";
    if (head === "dashboard"){
      const dv = ROUTE_DASH_VIEWS.includes(parts[1]) ? parts[1] : "cases";
      go("dashboard");
      if (view === "dashboard"){               // go() falls back to home for non-handlers
        setDashView(dv);
        // "new" never appears in a generated route (blank draft forms have no
        // deep link); a hand-typed /new URL self-heals via the replaceState below.
        const routeId = p => p && p !== "new" && ROUTE_ID.test(p);
        if (parts[2] === "case" && routeId(parts[3])) openCase(parts[3]);
        else if (dv === "wc" && routeId(parts[2])) wcOpen(parts[2]);
        else if (dv === "legal" && routeId(parts[2])) lgOpen(parts[2]);
      }
    }
    else if (["home","status","incident","request","lookup","employee-test"].includes(head)) go(head);
    else go("home");
  } finally { routeApplying = false; }
  // Normalize without adding a history entry (bad ids, non-handler fallbacks).
  history.replaceState(history.state, "", location.pathname + location.search + "#" + currentRoute());
  return true;
}
function applyInitialRoute(){
  if (!initialRoutePending) return false;
  initialRoutePending = false;
  return applyRoute();
}
function renderNav(){
  $("nav").innerHTML = session && !medicalInviteToken ? tabs().map(t=>`<button class="${view===t.id?'active':''}" onclick="go('${t.id}')">${t.label}</button>`).join("") : "";
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
  if(!ok) return `<div class="card login-card">
    <div class="banner err">Configuration needed: set <b>SUPABASE_URL</b> and <b>SUPABASE_ANON_KEY</b> in <code>config.js</code>. See the README.</div></div>`;
  return `<div class="card login-card">
    ${signedOutReason==="idle"?`<div class="banner warn" style="margin-bottom:14px"><b>You were signed out.</b> For security, standard sessions end after 24 hours without use. Sign in again to continue.</div>`:""}
    ${signedOutReason==="trusted-expired"?`<div class="banner warn" style="margin-bottom:14px"><b>Your 30-day sign-in expired.</b> Enter a new code to continue.</div>`:""}
    ${signedOutReason==="account-changed"?`<div class="banner warn" style="margin-bottom:14px"><b>The remembered account did not match this session.</b> Sign in again to continue.</div>`:""}
    <div class="login-mark" aria-hidden="true">PS</div>
    <p class="login-eyebrow">People Support Portal</p>
    <h2 class="section">${auth.sent?'Check your email':'Welcome'}</h2>
    <p class="login-lede">${auth.sent?`Enter the code sent to <b>${esc(auth.email)}</b>.`:`We'll email you a secure sign-in code. Use the address where you want to receive it.`}</p>
    ${!auth.sent ? `
      <label for="otp-email">Email address</label>
      <input id="otp-email" type="email" placeholder="you@example.com" autocomplete="email" value="${esc(auth.email)}" onkeydown="if(event.key==='Enter')sendOtp()">
      <label class="role-opt login-remember"><input type="checkbox" ${auth.remember?'checked':''} onchange="setRememberDevice(this.checked)"> Keep me logged in on this device</label>
      <p class="login-help">Use this only on a private device. It keeps you signed in for up to 30 days.</p>
      <div class="login-actions"><button class="btn" onclick="sendOtp()" ${busy?'disabled':''}>${busy?'<span class="spin"></span> Sending…':'Continue'}</button></div>`
    : `
      <label for="otp-code">6-digit code</label>
      <input id="otp-code" class="otp-code" type="text" placeholder="000000" autocomplete="one-time-code" inputmode="numeric" pattern="[0-9]{6}" maxlength="6" aria-describedby="otp-help" oninput="this.value=this.value.replace(/\D/g,'').slice(0,6)" onkeydown="if(event.key==='Enter')verifyOtp()">
      <p id="otp-help" class="login-help">The code expires soon and can only be used once. Check your spam folder if it hasn't arrived.</p>
      <div class="login-actions">
        <button class="btn" onclick="verifyOtp()" ${busy?'disabled':''}>${busy?'<span class="spin"></span> Checking…':'Sign in'}</button>
        <button class="btn ghost" onclick="(function(){window.dispatchEvent(new Event('otp-reset'))})()" id="otp-back">Change email</button>
      </div>`}
    ${auth.err?`<div class="banner err">${esc(auth.err)}</div>`:""}
    <p class="login-security">Looking for a report you submitted? Sign in, then choose <b>Check my report status</b>.</p>
  </div>`;
}
function setRememberDevice(on){ auth.remember = !!on; }
window.addEventListener("otp-reset", ()=>{ auth={email:"",sent:false,err:"",remember:false}; render(); });

// ---------------- HOME (question vs incident fork) ----------------
function renderEmployeeTest(){
  return `<div class="card" style="max-width:760px;margin:0 auto">
    <h2 class="section">Test the employee experience</h2>
    <p>Use your current sign-in to try an anonymous report, save its claim code, and exchange messages with the assigned handler.</p>
    <div class="banner warn"><b>This creates a real test case.</b> Normal routing and permitted email notifications run. Use made-up details and harmless sample files. Close the case as <b>Test</b> when finished, before the next reporting snapshot.</div>
    <ol><li>Start the anonymous report below. The form includes a test label and a non-store location.</li>
      <li>Submit once, save the reference and claim code, then check the report and send a sample message.</li>
      <li>Return to HR. Have the assigned handler check that the reporter is shown as Anonymous and reply. Use the claim code to read their reply.</li>
      <li>Ask the assigned handler to close it using <b>Test</b>.</li></ol>
    <p class="note-sm">Your HR permissions remain unchanged. This checks the reporting experience; a separate non-HR email sign-in is still needed to verify employee access restrictions and the sign-in code. Reporter email delivery also depends on the current tester allowlist.</p>
    <button class="btn" onclick="startEmployeeTest()">Start anonymous test report</button>
    ${employeeTestReceipt?`<p>Last test in this session: <b>${esc(employeeTestReceipt.ref)}</b>. Save your claim code before refreshing or signing out.</p><button class="btn sec" onclick="openEmployeeTestStatus()">Check last test report</button>`:""}
  </div>`;
}
function employeeTestBanner(){
  return employeeTest ? `<div class="banner warn" style="margin-bottom:16px"><b>Employee test in progress.</b> This is a real case with normal routing, using your HR sign-in. Keep all details fictional and close it as <b>Test</b> afterward. <button class="btn sm sec" onclick="endEmployeeTest()" ${busy?'disabled':''}>Return to HR</button></div>` : "";
}
function startEmployeeTest(){
  if(!session || !isHandler || busy) return;
  if((form.description.trim() || form.files?.length || form.parties.length) && !confirm("Replace the current incident draft with a fictional test report?")) return;
  if(showManual){ syncManualFields(); flushManualDraft(true); }
  employeeTest=true;
  form=blankIncident(); form.anonymous=true; form.category="Other";
  form.location=OTHER_LOCATION; form.email=verifiedEmail();
  form.description="Fictional test report to check submission, claim-code access, and two-way messages. No real incident or person is involved.";
  partySearchResults=[]; partySearchError="";
  go("incident");
}
function endEmployeeTest(){
  if(busy) return;
  if(employeeTest && (form.description.trim() || form.files?.length || form.parties.length) && !confirm("Leave this test draft? It has not been submitted.")) return;
  employeeTest=false; form=blankIncident(); form.email=verifiedEmail();
  go("dashboard");
}
async function openEmployeeTestStatus(){
  if(!session || !isHandler || busy || !employeeTestReceipt?.claim_code) return;
  if((form.description.trim() || form.files?.length || form.parties.length) && !confirm("Discard the current incident draft and open your last test report?")) return;
  form=blankIncident(); form.email=verifiedEmail();
  employeeTest=true; go("status");
  const input=$("cc"); if(input) input.value=employeeTestReceipt.claim_code;
  await doStatusCheck();
}
function renderHome(){
  return `${employeeTest?`<div style="max-width:720px;margin:24px auto 0">${employeeTestBanner()}</div>`:""}${trustedDeviceNotice?`<div class="banner ${usingTrustedSession()?'ok':'info'}" style="max-width:720px;margin:24px auto 0">${esc(trustedDeviceNotice)}</div>`:""}${receipt?`<div style="max-width:720px;margin:24px auto 0">${renderReceipt(receipt)}</div>`:""}
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
    <label for="q-location">Location (optional)</label>
    ${locationPicker("q-location", qform.location, "qformLoc", true)}
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
  qform.location = $("q-location")?.value ?? qform.location;
  errorMsg = "";
  const chosenLocation = canonicalLocation(qform.location);
  if(chosenLocation === null){ errorMsg=locationError(false); render(); return; }
  qform.location = chosenLocation;
  if(!qform.body.trim()){ errorMsg="Please describe your request."; render(); return; }
  if(!/^\S+@\S+\.\S+$/.test(qform.email)){ errorMsg="Please enter a valid email for the reply."; render(); return; }
  busy=true; render();
  let data, error;
  try {
    ({ data, error } = await sb.rpc("submit_case_v2", {
      p_intake_type:"request", p_category:qform.rtype, p_description:qform.body,
      p_anonymous:false, p_location:qform.location||null, p_relationship:null, p_role:null,
      p_contact_email:qform.email, p_contact_phone:null, p_parties:[], p_manual:false, p_incident_date:null,
      p_us_state:stateMap[qform.location]||null }));
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
  const handlerSearch = isHandler && !employeeTest;
  const results = f.pType==="employee" && directoryAllowed && f.pQuery.trim().length >= (handlerSearch ? 2 : 4)
    ? (handlerSearch ? employeeMatches(f.pQuery)   // shared accent-insensitive lookup (T136)
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
          ? `<span class="mini-l">Find the employee</span><input id="${pre}psearch" type="text" placeholder="${handlerSearch?'Search a name, title, or employee ID…':'Name or employee ID (at least 4 characters)…'}" value="${esc(f.pQuery)}" oninput="${P.input}(this.value)">`
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
    ${employeeTestBanner()}
    <p class="muted">Only the assigned HR handler can see this — never anyone the report is about.</p>

    <label for="f-location">Which location is this about?</label>
    ${locationPicker("f-location", form.location, "setIncidentLocation")}

    <label>When did this happen?</label>
    <input type="date" max="${todayStr()}" value="${esc(form.incidentDate)}" onchange="setF('incidentDate',this.value||todayStr(),true)">

    <label>How do you want to submit?</label>
    <div class="radio-cards">
      ${employeeTest?"":`<div class="radio-card ${!form.anonymous?'sel':''}" onclick="setF('anonymous',false)"><b>With my name</b><span class="muted">HR can follow up with you directly.</span></div>`}
      <div class="radio-card ${form.anonymous?'sel':''}" onclick="setF('anonymous',true)"><b>Anonymously</b><span class="muted">HR never sees who you are. You still get email updates, and a claim code for two-way messaging.</span></div>
    </div>
    ${form.anonymous?`<div class="banner ok" style="margin-top:10px">Your name is hidden from HR. Your email is stored securely <b>only</b> so the system can send you updates — the HR team cannot see it.</div>`:""}

    <label>What is your relationship to Earthbar?</label>
    <select onchange="setF('relationship',this.value)">${RELATIONSHIPS.map(r=>`<option ${form.relationship===r?'selected':''}>${r}</option>`).join("")}</select>
    ${form.relationship==="Employee"?`
      <label>Your current role at Earthbar</label>
      <input id="f-role" type="text" placeholder="e.g. Shift lead, EB Brentwood" value="${esc(form.role)}" oninput="setF('role',this.value,true)">`:""}

    <label for="f-category">Category</label>
    <select id="f-category" onchange="setF('category',this.value)">${CATEGORIES.map(c=>`<option ${form.category===c?'selected':''}>${c}</option>`).join("")}</select>
    <p class="note-sm">Pick the closest fit — HR reviews and classifies every report after it's submitted.</p>

    ${partyBuilder(form,"")}

    <label>What happened?</label>
    <textarea id="f-desc" placeholder="Describe the situation.${form.anonymous?' If anonymous, avoid details that would reveal who you are.':''}" oninput="setF('description',this.value,true)">${esc(form.description)}</textarea>

    <label>Relevant documents <span class="muted" style="font-weight:400">(optional)</span></label>
    <p class="note-sm" style="margin:0 0 6px">If you have any relevant documents for this case, please submit them — photos, screenshots, PDFs.</p>
    <input id="f-files" type="file" multiple onchange="setF('files',Array.from(this.files),true)">
    ${form.files?.length?`<p class="note-sm">Selected: ${form.files.map(f=>esc(f.name)).join(", ")}</p>`:""}

    <label>Verified sign-in email <span class="muted" style="font-weight:400">(for your case confirmation and updates)</span></label>
    <input id="f-email" type="email" value="${esc(verifiedEmail())}" readonly>
    <p class="note-sm">Nobody sees this address — it goes only to the automated inbox that sends your confirmation and case updates.</p>
    <label>Your phone <span class="muted" style="font-weight:400">(optional)</span></label>
    <input id="f-phone" type="text" value="${esc(form.phone)}" oninput="setF('phone',this.value,true)">

    <div id="incident-error" aria-live="polite">${errorMsg?`<div class="banner err">${esc(errorMsg)}</div>`:""}</div>
    <div style="margin-top:18px"><button id="incident-submit" class="btn" onclick="submitIncident()" ${busy?'disabled':''}>${busy?'<span class="spin"></span> Submitting…':'Submit report'}</button></div>
  </div>${receipt?renderReceipt(receipt):""}`;
}
function paintIncidentStatus(){
  const errorBox = $("incident-error"), submitButton = $("incident-submit");
  if(errorBox) errorBox.innerHTML = errorMsg ? `<div class="banner err">${esc(errorMsg)}</div>` : "";
  if(submitButton){
    submitButton.disabled = busy;
    submitButton.innerHTML = busy ? '<span class="spin"></span> Submitting…' : 'Submit report';
  }
}
function setF(k,v,silent){ if(employeeTest && k==="anonymous") v=true; form[k]=v; if(!silent) render(); }
function setIncidentLocation(value){ form.location=value; form.usState=stateMap[value]||""; }
function onPartyInput(v){
  form.pQuery=v; partySearchResults=[]; partySearchError=""; render();
  let el=$("psearch"); if(el){el.focus();el.setSelectionRange(v.length,v.length);}
  const query = v.trim();
  clearTimeout(partySearchTimer);
  const seq = ++partySearchSeq;
  if((isHandler && !employeeTest) || !canUseDirectorySearch() || query.length < 4) return;
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
  if(busy) return;
  const epoch = sessionEpoch;
  form.description = $("f-desc")?.value ?? form.description ?? "";
  form.email = verifiedEmail(); form.phone = (($("f-phone")?.value ?? form.phone)||"").trim();
  form.role = form.relationship==="Employee" ? ($("f-role")?.value||form.role||"") : "";
  form.location = $("f-location")?.value ?? form.location;
  const selectedFiles = Array.from($("f-files")?.files || []);
  const files = selectedFiles.length ? selectedFiles : (form.files || []);
  errorMsg=""; paintIncidentStatus();
  const chosenLocation = canonicalLocation(form.location, true);
  if(!chosenLocation){ errorMsg=locationError(true); paintIncidentStatus(); return; }
  form.location = chosenLocation; form.usState = stateMap[chosenLocation] || "";
  if(!form.description.trim()){ errorMsg="Please describe what happened."; paintIncidentStatus(); return; }
  if(!/^\S+@\S+\.\S+$/.test(form.email)){ errorMsg="An email is required so we can confirm your report and send updates (it's hidden from HR if you're anonymous)."; paintIncidentStatus(); return; }
  busy=true; paintIncidentStatus();
  let data, error;
  try {
    ({ data, error } = await sb.rpc("submit_case_v2", {
      p_intake_type:"incident", p_category:form.category, p_description:employeeTest ? `${EMPLOYEE_TEST_PREFIX}\n\n${form.description}` : form.description,
      p_anonymous:employeeTest || form.anonymous, p_location:form.location, p_relationship:form.relationship,
      p_role:form.role||null, p_contact_email:form.email, p_contact_phone:form.phone||null,
      p_parties:form.parties, p_manual:false, p_incident_date:form.incidentDate, p_us_state:form.usState||null }));
  } catch(e) { error = e; }
  if(epoch !== sessionEpoch) return;
  if(error){ busy=false; errorMsg = errText(error); paintIncidentStatus(); return; }
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
  receipt = Object.assign({upNote, employeeTest}, data);
  if(employeeTest) employeeTestReceipt={ref:data.ref,claim_code:data.claim_code};
  form = blankIncident(); form.email = verifiedEmail();
  view = "home";   // land back on the home screen with the confirmation on top
  render(); window.scrollTo({top:0,behavior:"smooth"});
}
function renderReceipt(r){
  if(r.question) return `<div class="card"><div class="banner ok"><b>Sent to HR.</b> Reference <span class="ref">${esc(r.ref)}</span> — you'll get a reply at the email you provided.</div></div>`;
  return `<div class="card">
    ${r.employeeTest?`<div class="banner warn"><b>Test case created.</b> Save your reference and claim code. Normal routing applies; close this case as <b>Test</b> after the exercise.</div>`:""}
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
    ${r.employeeTest?`<div class="row" style="margin-top:16px"><button class="btn sec" onclick="openEmployeeTestStatus()">Check test report and messages</button><button class="btn sec" onclick="endEmployeeTest()">Return to HR</button></div>`:""}
  </div>`;
}

// ---------------- DASHBOARD ----------------
function setFilter(k,v){ filters[k]=v; }
function activeDashboardFilterCount(){
  // pfrom/pto ride along with the custom period selection — not separate filters
  return Object.entries(filters).filter(([key,value]) =>
    !["pfrom","pto"].includes(key) && (key === "q" ? String(value).trim() : value)).length;
}
function filterButtonText(){
  const n = activeDashboardFilterCount();
  return `${showFilters?'Hide filters':'Filters'}${n?` (${n})`:''}`;
}
function syncDashboardFilterInputs(){
  const panel = $("dashboard-filters");
  if (!panel) return;
  panel.querySelectorAll("[data-filter-key]").forEach(input => { input.value = filters[input.dataset.filterKey] || ""; });
  const range = $("flt-period-range");
  if (range) range.hidden = filters.period !== CUSTOM_PERIOD;
}
// T135 QC: from > to in the custom range silently matches nothing — surface it
// inline (scoped repaint via updateDashboardResults; inputs are never re-rendered
// mid-typing). ISO yyyy-mm-dd strings compare correctly as plain strings.
const customRangeInverted = () =>
  filters.period === CUSTOM_PERIOD && !!filters.pfrom && !!filters.pto && filters.pfrom > filters.pto;
function setPeriodFilter(value){
  filters.period = value;
  if (value !== CUSTOM_PERIOD){ filters.pfrom = ""; filters.pto = ""; }
  syncDashboardFilterInputs();
  applyFilters();
}
function toggleFilters(){
  showFilters = !showFilters;
  const panel = $("dashboard-filters"), button = $("filter-toggle");
  if (!panel || !button) return;
  panel.classList.toggle("is-open", showFilters);
  panel.setAttribute("aria-hidden", String(!showFilters));
  panel.inert = !showFilters;
  button.setAttribute("aria-expanded", String(showFilters));
  button.textContent = filterButtonText();
}
function clearDashboardFilters(){
  filters = blankDashboardFilters();
  syncDashboardFilterInputs();
  updateDashboardResults();
}
function clearDashboardFilter(key){
  if (!Object.prototype.hasOwnProperty.call(filters,key)) return;
  filters[key] = "";
  if (key === "period"){ filters.pfrom = ""; filters.pto = ""; }
  syncDashboardFilterInputs();
  updateDashboardResults();
}
function setDashboardQuickFilter(kind){
  filters.quick = filters.quick === kind ? "" : kind;
  updateDashboardResults();
}
function toggleMyWork(){
  filters.mine = filters.mine ? "" : "yes";
  updateDashboardResults();
}
function applyFilters(){
  filters.q = $("flt-q")?.value ?? filters.q;
  updateDashboardResults();
}
function setDashView(v){ if (showManual){ syncManualFields(); flushManualDraft(true); } closeAttachmentPreview(false); setLegalPreviewBackgroundInert(false); dashView=v; showManual=false; dashSort={ key:"", dir:1 }; wcSelected=null; wcFilters={ q:"", status:"", state:"", asg:"", quick:"" }; wcData=[]; wcSort={ key:"", dir:1 }; lgSelected=null; lgFilters={ q:"", state:"", risk:"", status:"", type:"", quick:"active" }; legalData=[]; lgSort={ key:"", dir:1 }; lgEditing=false; legalDetail={notes:[],files:[],errors:[]}; legalComposer={caseId:null,note:"",files:[],status:"",error:"",noteError:"",retry:false}; legalBusy={note:false,upload:false}; legalPreview={open:false,caseId:null,storedName:"",name:"",url:"",kind:""}; legalPreviewGeneration+=1; filters=blankDashboardFilters(); render(); syncRoute(); }
// NOTE: no select("*") on cases — reporter_email/phone are column-locked
// server-side (anonymity guarantee); requesting them is permission-denied.
// closure_category/closure_ref need migration 017 (granted there per 012's rule).
// Module-level: also the raw column list for the CSV export.
const DASH_CASE_COLS = "id,ref,category,description,severity,anonymous,handler_id,external,route_reason,state,created_at,closed_at,incident_date,intake_type,location,us_state,reporter_relationship,reporter_role,reporter_display,risk_level,substantiated,substantiated_note,policies,ai_summary,manual_entry,updated_at,accommodation_status,accommodation_start,accommodation_end,accommodation_duration,closure_category,closure_ref,requester_id";
const dashboardOverdue = (c, now=Date.now()) => (c.tasks||[]).some(t => t.status==="open" && t.due_at && new Date(t.due_at).getTime() < now);
// This is a view of already-authorized rows, never an authorization substitute.
// Fail closed when the signed-in email has no unique directory employee match.
function myWorkEmployeeId(){
  const email = (session?.user?.email || "").trim().toLowerCase();
  if (!email || !isHandler) return null;
  const matches = dirList.filter(d => (d.email || "").trim().toLowerCase() === email);
  return matches.length === 1 ? matches[0].employee_id || null : null;
}
function myWorkDeadline(c){
  const due = (c.tasks || []).filter(t => t.status === "open" && t.due_at)
    .map(t => Date.parse(t.due_at)).filter(Number.isFinite);
  return due.length ? Math.min(...due) : Infinity;
}
function compareMyWork(a, b, now){
  const rank = c => ({High:0, Medium:1, Low:2}[caseRisk(c)] ?? 3);
  const opened = c => Number.isFinite(Date.parse(c.created_at)) ? Date.parse(c.created_at) : Infinity;
  return Number(dashboardOverdue(b,now)) - Number(dashboardOverdue(a,now)) ||
    rank(a) - rank(b) || myWorkDeadline(a) - myWorkDeadline(b) ||
    opened(a) - opened(b) || String(a.id).localeCompare(String(b.id));
}
const dashboardInvolved = c => (c.case_parties||[]).map(p =>
  p.party_type==="customer" || (!p.subject_id && p.display_name) ? `${p.display_name||"Customer"} (customer)` : nameOf(p.subject_id)
).filter(Boolean).join(", ");
const dashboardLocState = c => c.location ? `${esc(c.location)}${c.us_state?`, ${esc(c.us_state)}`:""}` : (c.us_state?esc(c.us_state):"—");
// T136: who a request is for. Live directory rows show "Name (EID)"; if the
// employee later leaves the directory the recorded name (reporter_display)
// still renders. Returns plain text — callers esc().
const requesterLine = c => {
  if (c.requester_id){
    const d = dirMap[c.requester_id];
    if (d) return `${d.name} (${d.employee_id})`;
  }
  return c.reporter_display || "";
};
// T136: column sorting shared by the cases / requests / closed tabs. Value
// extractors return a number or a string; strings compare accent-insensitively
// (so "José" files under J). Extractors run only while a sort is active.
let dashSort = { key:"", dir:1 };
const DASH_SORT_VALS = {
  ref: c => c.ref || "",
  risk: c => ({High:0,Medium:1,Low:2}[caseRisk(c)] ?? 3),
  cat: c => c.category || "",
  opened: c => Date.parse(c.created_at) || 0,
  loc: c => (c.location || "") + (c.us_state ? ", " + c.us_state : ""),
  reporter: c => c.anonymous ? "anonymous" : (requesterLine(c) || ""),
  involved: c => dashboardInvolved(c),
  handler: c => c.external ? "external advisor" : nameOf(c.handler_id),
  state: c => stlabel(c.state) || "",
  days: c => (c.closed_at ? new Date(c.closed_at).getTime() : Date.now()) - new Date(c.created_at).getTime(),
  sla: c => Number(dashboardOverdue(c)),
  outcome: c => c.accommodation_status || "",
  type: c => c.intake_type === "request" ? "Request" : "Incident",
  closed: c => c.closed_at ? (Date.parse(c.closed_at) || 0) : 0,
  closure: c => c.closure_category || "",
};
function dashCompare(a, b){
  const value = DASH_SORT_VALS[dashSort.key];
  const va = value(a), vb = value(b);
  const cmp = (typeof va === "number" && typeof vb === "number")
    ? va - vb
    : String(va).localeCompare(String(vb), undefined, { sensitivity:"base" });
  return (cmp || String(a.ref || a.id).localeCompare(String(b.ref || b.id))) * dashSort.dir;
}
function dashboardModel(){
  const isReq = dashView === "requests";
  const isClosed = dashView === "closed";
  const pool = dashboardData.filter(c => isClosed
    ? c.state === "Closed"
    : (isReq ? c.intake_type === "request" : c.intake_type !== "request") && c.state !== "Closed");
  const now = Date.now();
  const q = filters.q.trim().toLowerCase();
  const employeeId = filters.mine ? myWorkEmployeeId() : null;
  const shown = pool.filter(c =>
    (!filters.mine || (employeeId && c.handler_id === employeeId && !c.external && c.state !== "Closed")) &&
    (!filters.quick ||
      (filters.quick==="open" && c.state!=="Closed") ||
      (!isReq && filters.quick==="high" && caseRisk(c)==="High") ||
      (!isReq && filters.quick==="overdue" && dashboardOverdue(c,now))) &&
    (isReq || !filters.risk || caseRisk(c)===filters.risk) &&
    (!filters.cat || c.category===filters.cat) &&
    (!filters.state || c.state===filters.state) &&
    (!filters.handler || (filters.handler==="__ext" ? c.external : c.handler_id===filters.handler)) &&
    (!(isReq || isClosed) || !filters.acc || (c.intake_type==="request" && (filters.acc==="__none" ? !c.accommodation_status : c.accommodation_status===filters.acc))) &&
    (!(isReq || isClosed) || !filters.dur || (c.intake_type==="request" && c.accommodation_duration===filters.dur)) &&
    (!filters.us || c.us_state===filters.us) &&
    (!filters.loc || c.location===filters.loc) &&
    (!filters.leader || caseDistrictLeader(c)===filters.leader) &&
    caseOpenedInPeriod(c, filters.period) &&
    (!q || [c.ref,c.description,c.location,dashboardInvolved(c),requesterLine(c)].some(v => (v||"").toLowerCase().includes(q)))
  );
  if (filters.mine) shown.sort((a,b) => compareMyWork(a,b,now));
  // An explicit column sort overrides the My Work urgency order until cleared.
  if (dashSort.key && DASH_SORT_VALS[dashSort.key]) shown.sort(dashCompare);
  return { isReq, isClosed, pool, shown, now };
}
function dashboardFilterChipEntries(){
  const isReq = dashView === "requests";
  const isClosed = dashView === "closed";
  const quickLabels = isReq
    ? { open:"Open requests" }
    : { open:"Open cases", high:"High risk", overdue:"SLA overdue" };
  const entries = [];
  if (filters.mine) entries.push({ key:"mine", label:"My Work: open, assigned to me" });
  if (filters.quick && quickLabels[filters.quick]) entries.push({ key:"quick", label:quickLabels[filters.quick] });
  if (filters.q.trim()) entries.push({ key:"q", label:`Search: “${filters.q.trim()}”` });
  const labels = {
    risk:"Risk", cat:isReq?"Request type":"Category", state:isReq?"Request status":"Status",
    handler:isReq?"Case owner":(isClosed?"Owner / handler":"Handler"), acc:"Outcome", dur:"Duration", us:"Location state",
    loc:"Location", leader:"District leader", period:"Period"
  };
  for (const key of ["risk","cat","state","handler","acc","dur","us","loc","leader","period"]){
    if (!filters[key]) continue;
    let value = filters[key];
    if (key === "handler") value = value === "__ext" ? "External advisor" : nameOf(value);
    if (key === "acc" && value === "__none") value = "Not yet decided";
    if (key === "state") value = stlabel(value);
    if (key === "leader") value = districtLeaderLabel(value);
    if (key === "period") value = value === CUSTOM_PERIOD
      ? `Custom ${filters.pfrom || "…"} → ${filters.pto || "…"}`
      : (FISCAL_PERIODS[value]?.label || value);
    entries.push({ key, label:`${labels[key]}: ${value}` });
  }
  return entries;
}
function dashboardActiveFiltersHtml(){
  const entries = dashboardFilterChipEntries();
  if (!entries.length) return "";
  return `<span class="active-filter-label">Active filters</span>${entries.map(({key,label}) =>
    `<button type="button" class="filter-chip" aria-label="Remove ${esc(label)} filter" onclick="clearDashboardFilter('${key}')"><span>${esc(label)}</span><span class="filter-chip-x" aria-hidden="true">×</span></button>`
  ).join("")}`;
}
function dashboardRowsHtml({isReq,isClosed,shown,now}){
  if (isClosed) return shown.length ? shown.map(c=>{
    const request = c.intake_type === "request";
    return `<tr class="clk" onclick="openCase('${c.id}')">
      <td style="padding-left:20px"><button type="button" class="row-link ref" aria-label="Open closed ${request?'request':'case'} ${esc(c.ref)}" onclick="event.stopPropagation();openCase('${c.id}')">${esc(c.ref)}</button></td>
      <td><span class="chip">${request?'Request':'Incident'}</span></td><td>${esc(c.category)}</td><td>${fmtD(c.created_at)}</td><td>${dashboardLocState(c)}</td>
      <td>${c.anonymous?'Anonymous':esc(requesterLine(c)||'—')}</td><td>${c.external?'External advisor <span class="warnbadge">EXT</span>':esc(nameOf(c.handler_id))}</td>
      <td>${c.closed_at?fmtD(c.closed_at):'—'}</td><td>${closureLine(c)||'<span class="muted">—</span>'}</td>
    </tr>`;
  }).join("") : `<tr><td colspan="9" class="empty-row">No closed cases or requests match these filters.</td></tr>`;
  if (isReq) return shown.length ? shown.map(c=>`<tr class="clk" onclick="openCase('${c.id}')">
    <td style="padding-left:20px"><button type="button" class="row-link ref" aria-label="Open request ${esc(c.ref)}" onclick="event.stopPropagation();openCase('${c.id}')">${esc(c.ref)}</button></td>
    <td>${esc(c.category)}</td><td>${fmtD(c.created_at)}</td><td>${dashboardLocState(c)}</td><td>${esc(requesterLine(c)||'—')}</td>
    <td>${c.external?'External advisor <span class="warnbadge">EXT</span>':esc(nameOf(c.handler_id))}</td>
    <td>${pill(c.state)}${closureLine(c)}</td><td>${accPill(c.accommodation_status)}</td>
  </tr>`).join("") : `<tr><td colspan="8" class="empty-row">No requests match these filters.</td></tr>`;
  return shown.length ? shown.map(c=>`<tr class="clk ${dashboardOverdue(c,now)?'overdue':''}" onclick="openCase('${c.id}')">
    <td style="padding-left:20px"><button type="button" class="row-link ref" aria-label="Open case ${esc(c.ref)}" onclick="event.stopPropagation();openCase('${c.id}')">${esc(c.ref)}</button></td><td>${riskPill(caseRisk(c))}</td>
    <td>${esc(c.category)}</td><td>${fmtD(c.created_at)}</td><td>${dashboardLocState(c)}</td>
    <td>${c.anonymous?'<span class="chip">Anonymous</span>':esc(requesterLine(c)||'Named')}</td><td>${esc(dashboardInvolved(c))||'—'}</td>
    <td>${c.external?'External advisor <span class="warnbadge">EXT</span>':esc(nameOf(c.handler_id))}</td>
    <td>${pill(c.state)}${closureLine(c)}</td><td>${daysOpen(c,now)}</td>
    <td>${dashboardOverdue(c,now)?'<span class="pill due-over">Overdue</span>':'<span class="pill due-ok">On track</span>'}</td>
  </tr>`).join("") : `<tr><td colspan="11" class="empty-row">No cases match these filters.</td></tr>`;
}
// T136: the three dashboard tabs share one sortable header model — the
// requests tab mirrors the cases tab (same filter panel, sortable columns,
// and a location column).
const DASH_COLUMNS = {
  closed: [["ref","Ref"],["type","Type"],["cat","Category"],["opened","Opened"],["loc","Location"],["reporter","Reporter / requester"],["handler","Owner / handler"],["closed","Closed on"],["closure","Closure"]],
  requests: [["ref","Ref"],["cat","Request type"],["opened","Opened"],["loc","Location"],["reporter","Requester"],["handler","Case owner"],["state","State"],["outcome","Outcome"]],
  cases: [["ref","Ref"],["risk","Risk"],["cat","Category"],["opened","Opened"],["loc","Location"],["reporter","Reporter"],["involved","Involved"],["handler","Handler"],["state","Status"],["days","Days open"],["sla","SLA"]],
};
function dashHeadHtml(isReq, isClosed){
  return DASH_COLUMNS[isClosed ? "closed" : (isReq ? "requests" : "cases")].map(([key,label], i) => {
    const active = dashSort.key === key;
    return `<th data-sort-key="${key}" aria-sort="${active?(dashSort.dir===1?'ascending':'descending'):'none'}"${i===0?' style="padding-left:20px"':''}><button type="button" class="th-sort" onclick="setDashSort('${key}')">${esc(label)}<span class="sort-ind" aria-hidden="true">${active?(dashSort.dir===1?'▲':'▼'):''}</span></button></th>`;
  }).join("");
}
function setDashSort(key){
  if (!DASH_SORT_VALS[key]) return;
  if (dashSort.key === key) dashSort.dir = -dashSort.dir;
  else dashSort = { key, dir:1 };
  updateDashboardResults();
}
function updateDashboardResults(){
  const body = $("dashboard-table-body");
  if (!body) return;
  const model = dashboardModel();
  document.querySelectorAll("#dashboard-table th[data-sort-key]").forEach(th => {
    const active = dashSort.key === th.dataset.sortKey;
    th.setAttribute("aria-sort", active ? (dashSort.dir===1?"ascending":"descending") : "none");
    const ind = th.querySelector(".sort-ind");
    if (ind) ind.textContent = active ? (dashSort.dir===1?"▲":"▼") : "";
  });
  body.innerHTML = dashboardRowsHtml(model);
  lastShown = model.shown;
  const result = $("dashboard-result-count");
  if (result) result.textContent = `Showing ${model.shown.length} of ${model.pool.length} ${model.isClosed?'closed items':(model.isReq?'requests':'cases')}`;
  const activeFilters = $("dashboard-active-filters");
  if (activeFilters) activeFilters.innerHTML = dashboardActiveFiltersHtml();
  const rangeWarn = $("flt-range-warn");
  if (rangeWarn) rangeWarn.hidden = !customRangeInverted();
  const toggle = $("filter-toggle");
  if (toggle) toggle.textContent = filterButtonText();
  const mine = $("my-work-toggle");
  if (mine) { mine.classList.toggle("ghost", !filters.mine); mine.setAttribute("aria-pressed", String(!!filters.mine)); }
  const mineHint = $("my-work-hint");
  if (mineHint) { mineHint.hidden = !filters.mine; mineHint.textContent = myWorkHint(); }
  document.querySelectorAll("[data-quick-filter]").forEach(tile => {
    const active = filters.quick === tile.dataset.quickFilter;
    tile.classList.toggle("active", active);
    tile.setAttribute("aria-pressed", String(active));
  });
}
function myWorkHint(){
  return myWorkEmployeeId()
    ? "My Work shows open items assigned to you in this tab, with any other filters applied. Order: overdue first, then risk (High, Medium, Low, unset), earliest open-task deadline, then oldest opened. Clicking a column header re-sorts these items until you switch tabs."
    : "My Work is unavailable because your sign-in could not be matched to one directory employee. Ask an administrator to check your directory email. Clear My Work to return to all accessible items.";
}
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
  dashboardData = all || [];
  const { isReq, isClosed, pool, shown, now } = dashboardModel();
  const open = pool.filter(c=>c.state!=="Closed").length;
  const closedIncidents = pool.filter(c=>c.intake_type!=="request").length;
  const closedRequests = pool.filter(c=>c.intake_type==="request").length;
  const hi = pool.filter(c=>caseRisk(c)==="High").length;
  const od = pool.filter(c=>dashboardOverdue(c,now)).length;
  // Filter options come from FIXED lists (plus anything present in the data), so
  // every category/state/team-member is offered even before any case uses it.
  const catOpts = [...new Set([...(isClosed?[...CATEGORIES,...REQUEST_TYPES]:(isReq?REQUEST_TYPES:CATEGORIES)), ...pool.map(c=>c.category)])].filter(Boolean);
  const stateOpts = isReq ? [...REQ_STATES]
                          : [...new Set([...INCIDENT_STATES,"Reopened", ...pool.map(c=>c.state).filter(s=>s!=="Closed")])];
  const handlers = hrTeam.map(t=>[t.employee_id, nameOf(t.employee_id)]);
  // Store-level location options: full store list + anything already on a case.
  const locOpts = [...new Set([...storeList, OTHER_LOCATION, ...pool.map(c=>c.location)])].filter(Boolean);
  lastShown = shown;   // what Export CSV downloads — exactly the filtered view
  el.innerHTML = `<div class="card">
      <div style="display:flex;align-items:center;gap:16px;flex-wrap:wrap">
        <h2 class="section" style="margin:0">HR dashboard</h2>
        <div class="dash-toggle">
          <button class="${dashView==='cases'?'on':''}" aria-pressed="${dashView==='cases'}" onclick="setDashView('cases')">Cases</button>
          <button class="${isReq?'on':''}" aria-pressed="${isReq}" onclick="setDashView('requests')">Requests</button>
          <button class="${isClosed?'on':''}" aria-pressed="${isClosed}" onclick="setDashView('closed')">Closed</button>
          <button aria-pressed="false" onclick="setDashView('wc')">Workers' Comp</button>
          <button aria-pressed="false" onclick="setDashView('legal')">Legal &amp; Claims</button>
        </div>
      </div>
      <div class="row dashboard-stats" style="margin:18px 0 4px">
         ${isClosed ? `
         <div class="stat"><div class="n">${pool.length}</div><div class="l">Closed items</div></div>
         <div class="stat"><div class="n">${closedIncidents}</div><div class="l">Incidents</div></div>
         <div class="stat"><div class="n">${closedRequests}</div><div class="l">Requests</div></div>` : `
         <button type="button" class="stat stat-button ${filters.quick==='open'?'active':''}" data-quick-filter="open" aria-pressed="${filters.quick==='open'}" onclick="setDashboardQuickFilter('open')"><div class="n">${open}</div><div class="l">Open ${isReq?'requests':'cases'}</div><div class="stat-hint">Filter table</div></button>
         ${isReq
          ? `<button type="button" class="stat stat-button" onclick="clearDashboardFilters()"><div class="n">${pool.length}</div><div class="l">Total requests</div><div class="stat-hint">Show all</div></button>`
          : `<button type="button" class="stat stat-button ${filters.quick==='high'?'active':''}" data-quick-filter="high" aria-pressed="${filters.quick==='high'}" onclick="setDashboardQuickFilter('high')"><div class="n" style="color:${hi?'var(--danger)':'var(--ok)'}">${hi}</div><div class="l">High risk</div><div class="stat-hint">Filter table</div></button>
             <button type="button" class="stat stat-button ${filters.quick==='overdue'?'active':''}" data-quick-filter="overdue" aria-pressed="${filters.quick==='overdue'}" onclick="setDashboardQuickFilter('overdue')"><div class="n" style="color:${od?'var(--warn)':'var(--ok)'}">${od}</div><div class="l">SLA overdue</div><div class="stat-hint">Filter table</div></button>`}`}
      </div>
      <div class="rule"></div>
      <div class="dash-actions">
         ${isClosed?'':`<button id="my-work-toggle" class="btn sm ${filters.mine?'':'ghost'}" aria-pressed="${!!filters.mine}" onclick="toggleMyWork()">My Work</button>`}
         <button id="filter-toggle" class="btn sm ghost" aria-controls="dashboard-filters" aria-expanded="${showFilters}" onclick="toggleFilters()">${filterButtonText()}</button>
        <button class="btn sm ghost" onclick="exportCasesCsv()">Export CSV</button>
        ${!isClosed?`<button class="btn sm sec" style="margin-left:auto" onclick="toggleManual()">${showManual?'Cancel manual entry':(isReq
          ?(hasManualDraft('request')?'Resume draft request':'+ Add request manually')
          :(hasManualDraft('case')?'Resume draft case':'+ Add case manually'))}</button>`:""}
      </div>
      ${isClosed?'':`<p id="my-work-hint" class="note-sm" ${filters.mine?'':'hidden'}>${esc(myWorkHint())}</p>`}
      <div id="dashboard-active-filters" class="active-filter-list" aria-live="polite">${dashboardActiveFiltersHtml()}</div>
      <div id="dashboard-filters" class="filters filter-panel ${showFilters?'is-open':''}" aria-hidden="${!showFilters}" ${showFilters?'':'inert'}>
        <div class="filter-panel-head"><div><b>Filter this dashboard</b><div id="dashboard-result-count" class="note-sm">Showing ${shown.length} of ${pool.length} ${isClosed?'closed items':(isReq?'requests':'cases')}</div></div><button class="btn sm ghost" onclick="clearDashboardFilters()">Clear all</button></div>
        <div class="filter-grid">
          <label class="filter-field filter-search"><span>Search</span><input id="flt-q" data-filter-key="q" type="text" placeholder="Ref, description, location, person…" value="${esc(filters.q)}" oninput="applyFilters()"></label>
          ${!isReq?`<label class="filter-field"><span>Risk</span><select data-filter-key="risk" onchange="setFilter('risk',this.value);applyFilters()"><option value="">All risks</option>${RISKS.map(r=>`<option ${filters.risk===r?'selected':''}>${r}</option>`).join("")}</select></label>`:""}
          <label class="filter-field"><span>${isReq?'Request type':'Category'}</span><select data-filter-key="cat" onchange="setFilter('cat',this.value);applyFilters()"><option value="">All</option>${catOpts.map(c=>`<option ${filters.cat===c?'selected':''}>${esc(c)}</option>`).join("")}</select></label>
          ${isClosed?'':`<label class="filter-field"><span>${isReq?'Request status':'Status'}</span><select data-filter-key="state" onchange="setFilter('state',this.value);applyFilters()"><option value="">All</option>${stateOpts.map(s=>`<option value="${s}" ${filters.state===s?'selected':''}>${stlabel(s)}</option>`).join("")}</select></label>`}
          ${isReq||isClosed?`<label class="filter-field"><span>Outcome</span><select data-filter-key="acc" onchange="setFilter('acc',this.value);applyFilters()"><option value="">All outcomes</option>${ACC_STATUS.map(s=>`<option ${filters.acc===s?'selected':''}>${s}</option>`).join("")}<option value="__none" ${filters.acc==='__none'?'selected':''}>Not yet decided</option></select></label>
          <label class="filter-field"><span>Duration</span><select data-filter-key="dur" onchange="setFilter('dur',this.value);applyFilters()"><option value="">All durations</option>${ACC_DURATION.map(d=>`<option ${filters.dur===d?'selected':''}>${d}</option>`).join("")}</select></label>`:""}
          <label class="filter-field"><span>${isReq?'Case owner':(isClosed?'Owner / handler':'Handler')}</span><select data-filter-key="handler" onchange="setFilter('handler',this.value);applyFilters()"><option value="">All</option>${handlers.map(([id,n])=>`<option value="${id}" ${filters.handler===id?'selected':''}>${esc(n)}</option>`).join("")}<option value="__ext" ${filters.handler==='__ext'?'selected':''}>External advisor</option></select></label>
          <label class="filter-field"><span>Location state</span><select data-filter-key="us" onchange="setFilter('us',this.value);applyFilters()"><option value="">All states</option>${statesList.map(s=>`<option ${filters.us===s?'selected':''}>${s}</option>`).join("")}</select></label>
          <label class="filter-field filter-wide-mobile"><span>Location</span><select id="flt-loc" data-filter-key="loc" onchange="setFilter('loc',this.value);applyFilters()"><option value="">All locations</option>${locOpts.map(name=>`<option value="${esc(name)}" ${filters.loc===name?'selected':''}>${esc(name)}</option>`).join("")}</select></label>
          <label class="filter-field filter-wide-mobile"><span>District leader</span><select id="flt-leader" data-filter-key="leader" onchange="setFilter('leader',this.value);applyFilters()"><option value="">All district leaders</option>${[...DISTRICT_LEADERS,"Other"].map(d=>`<option value="${esc(d)}" ${filters.leader===d?'selected':''}>${esc(districtLeaderLabel(d))}</option>`).join("")}</select></label>
          <label class="filter-field filter-wide-mobile"><span>Period</span><select id="flt-period" data-filter-key="period" onchange="setPeriodFilter(this.value)"><option value="">All periods</option>${Object.entries(FISCAL_PERIODS).map(([key,p])=>`<option value="${key}" ${filters.period===key?'selected':''}>${esc(p.label)}</option>`).join("")}<option value="${CUSTOM_PERIOD}" ${filters.period===CUSTOM_PERIOD?'selected':''}>Custom date range…</option></select></label>
          <div id="flt-period-range" class="filter-field filter-wide-mobile filter-range" ${filters.period===CUSTOM_PERIOD?'':'hidden'}><span>Opened between</span><div class="filter-range-inputs"><input type="date" data-filter-key="pfrom" aria-label="Opened on or after" value="${esc(filters.pfrom)}" onchange="setFilter('pfrom',this.value);applyFilters()"><span aria-hidden="true">–</span><input type="date" data-filter-key="pto" aria-label="Opened on or before" value="${esc(filters.pto)}" onchange="setFilter('pto',this.value);applyFilters()"></div><div id="flt-range-warn" class="note-sm" role="alert" style="color:var(--danger)" ${customRangeInverted()?'':'hidden'}>The first date is after the second, so no cases can match. Swap or adjust the dates.</div></div>
        </div>
      </div>
    </div>
    <div id="manualbox">${showManual&&!isClosed?(draftKindOf(manual)==="request"?renderManualRequest():renderManual()):""}</div>
    <div class="card" style="padding:8px 0;overflow-x:auto"><table id="dashboard-table">
      <thead><tr>${dashHeadHtml(isReq,isClosed)}</tr></thead>
      <tbody id="dashboard-table-body">${dashboardRowsHtml({isReq,isClosed,shown,now})}</tbody>
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
function trackerChipsHtml(entries, clearFn){
  if (!entries.length) return "";
  return `<span class="active-filter-label">Active filters</span>${entries.map(({key,label}) =>
    `<button type="button" class="filter-chip" aria-label="Remove ${esc(label)} filter" onclick="${clearFn}('${key}')"><span>${esc(label)}</span><span class="filter-chip-x" aria-hidden="true">×</span></button>`
  ).join("")}`;
}
// Sortable headers for the Workers' Comp and Legal tabs — same model as the
// cases/requests/closed tabs (T136): click toggles asc/desc, accent-insensitive
// string compare, ref as the stable tie-break, sort cleared on tab switch.
// A column with a falsy key (Legal "Docs") renders as a plain, unsortable th.
function trackerCompare(sort, vals){
  return (a, b) => {
    const value = vals[sort.key];
    const va = value(a), vb = value(b);
    const cmp = (typeof va === "number" && typeof vb === "number")
      ? va - vb
      : String(va).localeCompare(String(vb), undefined, { sensitivity:"base" });
    return (cmp || String(a.ref || a.id).localeCompare(String(b.ref || b.id))) * sort.dir;
  };
}
// Repaints patch the existing th's in place (like updateDashboardResults) —
// rebuilding the thead would tear out a focused header button mid-keyboard use.
function patchTrackerHead(rowId, sort){
  document.querySelectorAll(`#${rowId} th[data-sort-key]`).forEach(th => {
    const active = sort.key === th.dataset.sortKey;
    th.setAttribute("aria-sort", active ? (sort.dir===1?"ascending":"descending") : "none");
    const ind = th.querySelector(".sort-ind");
    if (ind) ind.textContent = active ? (sort.dir===1?"▲":"▼") : "";
  });
}
function trackerHeadHtml(columns, sort, setFnName){
  return columns.map(([key,label], i) => {
    if (!key) return `<th${i===0?' style="padding-left:20px"':''}>${esc(label)}</th>`;
    const active = sort.key === key;
    return `<th data-sort-key="${key}" aria-sort="${active?(sort.dir===1?'ascending':'descending'):'none'}"${i===0?' style="padding-left:20px"':''}><button type="button" class="th-sort" onclick="${setFnName}('${key}')">${esc(label)}<span class="sort-ind" aria-hidden="true">${active?(sort.dir===1?'▲':'▼'):''}</span></button></th>`;
  }).join("");
}
let wcSort = { key:"", dir:1 };
const WC_SORT_VALS = {
  ref: w => w.ref || "",
  employee: w => w.employee_name || "",
  loc: w => (w.location || "") + (w.us_state ? ", " + w.us_state : ""),
  injury: w => Date.parse(w.date_of_injury || "") || 0,
  body: w => w.body_part || "",
  type: w => w.claim_type || "",
  status: w => w.claim_status || "",
  work: w => w.work_status || "",
  incurred: w => Number(w.total_incurred) || 0,
  asg: w => w.assigned_to || "",
  followup: w => Date.parse(w.next_follow_up || "") || 0,
  days: w => wcDays(w.date_reported || (w.created_at||"").slice(0,10), w.date_closed || todayStr()) ?? -1,
};
const WC_COLUMNS = [["ref","Case ID"],["employee","Employee"],["loc","Location"],["injury","Injury / Reported"],["body","Body part"],["type","Claim type"],["status","Status"],["work","Work status"],["incurred","Incurred"],["asg","Assigned"],["followup","Next follow-up"],["days","Days open"]];
function setWcSort(key){
  if (!WC_SORT_VALS[key]) return;
  if (wcSort.key === key) wcSort.dir = -wcSort.dir;
  else wcSort = { key, dir:1 };
  updateWcResults();
}
function wcModel(){
  const q = wcFilters.q.trim().toLowerCase();
  const shown = wcData.filter(w =>
    (!wcFilters.status || w.claim_status === wcFilters.status) &&
    (!wcFilters.asg || w.assigned_to === wcFilters.asg) &&
    (!wcFilters.state || w.us_state === wcFilters.state) &&
    (!wcFilters.quick ||
      (wcFilters.quick === "open" && !WC_DEAD.includes(w.claim_status)) ||
      (wcFilters.quick === "legal" && (w.claim_status === "Litigation" || w.legal_escalation === "Yes")) ||
      (wcFilters.quick === "due" && wcFollowUpDue(w)) ||
      (wcFilters.quick === "osha" && w.osha_recordable === "Yes")) &&
    (!q || [w.ref, w.employee_name, w.claim_number, w.injury_description, w.location]
      .some(v => (v||"").toLowerCase().includes(q))));
  if (wcSort.key && WC_SORT_VALS[wcSort.key]) shown.sort(trackerCompare(wcSort, WC_SORT_VALS));
  return { rows:wcData, shown, todayS:todayStr() };
}
function wcRowsHtml({shown,todayS}){
  return shown.length ? shown.map(w=>{
    const dOpen = wcDays(w.date_reported || (w.created_at||"").slice(0,10), w.date_closed || todayS);
    return `<tr class="clk ${wcFollowUpDue(w)?'overdue':''}" onclick="wcOpen('${esc(w.id)}')">
      <td style="padding-left:20px"><button type="button" class="row-link ref" aria-label="Open claim ${esc(w.ref)}" onclick="event.stopPropagation();wcOpen('${esc(w.id)}')">${esc(w.ref)}</button>${w.legal_escalation==='Yes'?' <span class="warnbadge">LEGAL</span>':''}</td>
      <td>${esc(w.employee_name)}</td>
      <td>${esc(w.location||'—')}${w.us_state?`, ${esc(w.us_state)}`:''}</td>
      <td>${w.date_of_injury?fmtDateOnly(w.date_of_injury):'—'}${w.date_reported?` <span class="muted" style="font-size:11px">rpt ${fmtDateOnly(w.date_reported)}</span>`:''}</td>
      <td>${esc(w.body_part||'—')}</td><td>${esc(w.claim_type||'—')}</td><td>${wcPill(w.claim_status)}</td>
      <td>${esc(w.work_status||'—')}</td><td>${w.total_incurred ? '$'+Number(w.total_incurred).toLocaleString() : '$0'}</td>
      <td>${esc(w.assigned_to||'—')}</td>
      <td>${w.next_follow_up ? (wcFollowUpDue(w)?`<span class="pill due-over">${fmtDateOnly(w.next_follow_up)}</span>`:fmtDateOnly(w.next_follow_up)) : '—'}</td>
      <td>${dOpen==null?'—':dOpen}</td>
    </tr>`;
  }).join("") : `<tr><td colspan="12" class="empty-row">No claims match these filters.</td></tr>`;
}
function wcFilterChipsHtml(){
  const quick = {open:"Open claims",legal:"Legal / litigation",due:"Follow-ups due",osha:"OSHA recordable"};
  const entries = [];
  if (wcFilters.quick) entries.push({key:"quick",label:quick[wcFilters.quick]});
  if (wcFilters.q.trim()) entries.push({key:"q",label:`Search: “${wcFilters.q.trim()}”`});
  if (wcFilters.status) entries.push({key:"status",label:`Status: ${wcFilters.status}`});
  if (wcFilters.state) entries.push({key:"state",label:`State: ${wcFilters.state}`});
  if (wcFilters.asg) entries.push({key:"asg",label:`Assigned: ${wcFilters.asg}`});
  return trackerChipsHtml(entries,"clearWcFilter");
}
function syncWcFilterInputs(){
  [["wc-q","q"],["wc-f-status","status"],["wc-f-state","state"],["wc-f-asg","asg"]].forEach(([id,key])=>{ if ($(id)) $(id).value=wcFilters[key]; });
}
function updateWcResults(){
  const model = wcModel();
  patchTrackerHead("wc-table-head", wcSort);
  if ($("wc-table-body")) $("wc-table-body").innerHTML = wcRowsHtml(model);
  if ($("wc-result-count")) $("wc-result-count").textContent = `Showing ${model.shown.length} of ${model.rows.length} claims`;
  if ($("wc-active-filters")) $("wc-active-filters").innerHTML = wcFilterChipsHtml();
  document.querySelectorAll("[data-wc-quick-filter]").forEach(tile=>{
    const active = wcFilters.quick === tile.dataset.wcQuickFilter;
    tile.classList.toggle("active",active); tile.setAttribute("aria-pressed",String(active));
  });
}
// Filter interactions repaint the cached rows only. This avoids a loading flash,
// an unnecessary network request, and loss of unsaved editor fields.
function wcApplyFilters(){
  wcFilters.q      = $("wc-q")?.value        ?? wcFilters.q;
  wcFilters.status = $("wc-f-status")?.value ?? wcFilters.status;
  wcFilters.state  = $("wc-f-state")?.value  ?? wcFilters.state;
  wcFilters.asg    = $("wc-f-asg")?.value    ?? wcFilters.asg;
  updateWcResults();
}
function setWcQuickFilter(kind){ wcFilters.quick = wcFilters.quick === kind ? "" : kind; updateWcResults(); }
function clearWcFilter(key){ if (!(key in wcFilters)) return; wcFilters[key]=""; syncWcFilterInputs(); updateWcResults(); }
function clearWcFilters(){ wcFilters={q:"",status:"",state:"",asg:"",quick:""}; syncWcFilterInputs(); updateWcResults(); }
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
  wcData = list || [];
  const rows = wcData;
  const openN = rows.filter(w => !WC_DEAD.includes(w.claim_status)).length;
  const litN = rows.filter(w => w.claim_status === "Litigation" || w.legal_escalation === "Yes").length;
  const fuN = rows.filter(wcFollowUpDue).length;
  const oshaN = rows.filter(w => w.osha_recordable === "Yes").length;
  const incurred = rows.reduce((s,w)=>s+(Number(w.total_incurred)||0),0);
  const model = wcModel();
  // A stale selection (row no longer present) must not render as a "new" form —
  // saving it would target the missing id. Drop back to the list instead.
  if (wcSelected && wcSelected !== "new" && !rows.some(w => w.id === wcSelected)) wcSelected = null;
  const sel = wcSelected && wcSelected !== "new" ? rows.find(w => w.id === wcSelected) : null;
  el.innerHTML = `<div class="card">
      <div style="display:flex;align-items:center;gap:16px;flex-wrap:wrap">
        <h2 class="section" style="margin:0">HR dashboard</h2>
        <div class="dash-toggle">
          <button aria-pressed="false" onclick="setDashView('cases')">Cases</button>
          <button aria-pressed="false" onclick="setDashView('requests')">Requests</button>
          <button aria-pressed="false" onclick="setDashView('closed')">Closed</button>
          <button class="on" aria-pressed="true" onclick="setDashView('wc')">Workers' Comp</button>
          <button aria-pressed="false" onclick="setDashView('legal')">Legal &amp; Claims</button>
        </div>
      </div>
      <div class="row dashboard-stats" style="margin:18px 0 4px">
        <button type="button" class="stat stat-button ${wcFilters.quick==='open'?'active':''}" data-wc-quick-filter="open" aria-pressed="${wcFilters.quick==='open'}" onclick="setWcQuickFilter('open')"><div class="n">${openN}</div><div class="l">Open claims</div><div class="stat-hint">Filter table</div></button>
        <button type="button" class="stat stat-button ${wcFilters.quick==='legal'?'active':''}" data-wc-quick-filter="legal" aria-pressed="${wcFilters.quick==='legal'}" onclick="setWcQuickFilter('legal')"><div class="n" style="color:${litN?'var(--danger)':'var(--ok)'}">${litN}</div><div class="l">Legal / litigation</div><div class="stat-hint">Filter table</div></button>
        <button type="button" class="stat stat-button ${wcFilters.quick==='due'?'active':''}" data-wc-quick-filter="due" aria-pressed="${wcFilters.quick==='due'}" onclick="setWcQuickFilter('due')"><div class="n" style="color:${fuN?'var(--warn)':'var(--ok)'}">${fuN}</div><div class="l">Follow-ups due</div><div class="stat-hint">Filter table</div></button>
        <button type="button" class="stat stat-button ${wcFilters.quick==='osha'?'active':''}" data-wc-quick-filter="osha" aria-pressed="${wcFilters.quick==='osha'}" onclick="setWcQuickFilter('osha')"><div class="n">${oshaN}</div><div class="l">OSHA recordable</div><div class="stat-hint">Filter table</div></button>
        <button type="button" class="stat stat-button" onclick="clearWcFilters()"><div class="n">$${incurred.toLocaleString()}</div><div class="l">Total incurred</div><div class="stat-hint">Show all</div></button>
      </div>
      <div class="rule"></div>
      <div class="filter-panel-head tracker-filter-head"><div><b>Filter claims</b><div id="wc-result-count" class="note-sm">Showing ${model.shown.length} of ${model.rows.length} claims</div></div><button class="btn sm sec" onclick="wcOpen('new')">+ New claim</button></div>
      <div class="filter-grid tracker-filter-grid">
        <label class="filter-field filter-search"><span>Search</span><input id="wc-q" type="text" placeholder="Ref, employee, claim number…" value="${esc(wcFilters.q)}" oninput="wcApplyFilters()"></label>
        <label class="filter-field"><span>Status</span><select id="wc-f-status" onchange="wcApplyFilters()"><option value="">All statuses</option>${WC_CLAIM_STATUS.map(s=>`<option ${wcFilters.status===s?'selected':''}>${s}</option>`).join("")}</select></label>
        <label class="filter-field"><span>State</span><select id="wc-f-state" onchange="wcApplyFilters()"><option value="">All states</option>${WC_STATES.map(s=>`<option ${wcFilters.state===s?'selected':''}>${s}</option>`).join("")}</select></label>
        <label class="filter-field"><span>Assigned to</span><select id="wc-f-asg" onchange="wcApplyFilters()"><option value="">Anyone</option>${WC_ASSIGNEES.map(s=>`<option ${wcFilters.asg===s?'selected':''}>${s}</option>`).join("")}</select></label>
      </div>
      <div id="wc-active-filters" class="active-filter-list" aria-live="polite">${wcFilterChipsHtml()}</div>
    </div>
    ${wcSelected ? wcEditor(sel) : ""}
    <div class="card" style="padding:8px 0;overflow-x:auto"><table>
      <thead><tr id="wc-table-head">${trackerHeadHtml(WC_COLUMNS, wcSort, "setWcSort")}</tr></thead>
      <tbody id="wc-table-body">${wcRowsHtml(model)}</tbody>
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
    ${w?`<div class="mini-l" style="margin-top:12px">Claim documents</div>
    <div id="wc-docs-box">${wcDocsBoxHtml(w.id)}</div>`:""}
    <div id="wc-err"></div>
    <div class="mobile-form-actions"><button class="btn ghost" onclick="wcClose()">Cancel</button><button class="btn" onclick="wcSave()">${w?"Save changes":"Create claim"}</button></div>
  </div>`;
}
// ---- WC claim documents (mirrors the Legal related-documents pattern) ------
// Storage namespace wc/<claim-id>/ in the `evidence` bucket, HR handlers only,
// immutable once uploaded (migration 20260916190000). Unlike Legal, the claim
// editor around this section holds unsaved typed fields read from the DOM at
// save time, so NO document action may call render(): every repaint is scoped
// to #wc-docs-box. That is also why there is no preview modal here — the
// legal-style modal repaints the whole view; documents are download-to-view.
function blankWcDocs(caseId=null){ return { caseId, list:[], loaded:false, listError:"", files:[], status:"", error:"", busy:false, retry:false, seq:wcDocs.seq }; }
function wcStoragePath(caseId, storedName){
  const id = String(caseId||"");
  const name = String(storedName||"");
  if (!/^[A-Za-z0-9_-]{1,80}$/.test(id) || !name || /[\\/]/.test(name) || name === "." || name === "..") return null;
  return `wc/${id}/${name}`;
}
function wcDocsContext(caseId){
  const epoch=sessionEpoch, userId=session?.user?.id;
  const sameIdentity=()=>epoch===sessionEpoch && session?.user?.id===userId
    && wcSelected===caseId && wcDocs.caseId===caseId;
  return { sameIdentity, visible:()=>sameIdentity() && view==="dashboard" && dashView==="wc" };
}
function wcDocsBoxHtml(caseId){
  if (wcDocs.caseId!==caseId) return '<span class="muted">Loading documents…</span>';
  const docs = !wcDocs.loaded ? '<span class="muted">Loading documents…</span>'
    : wcDocs.list.length ? wcDocs.list.map(f=>{
        const display = legalDocumentName(f.name);
        return `<div class="task"><span><b>${esc(display)}</b><span class="muted" style="font-size:11px"> · ${fmtBytes(f.metadata?.size)}${f.created_at?` · ${fmt(f.created_at)}`:""}</span></span>
          <span style="margin-left:auto"><button class="btn sm ghost" data-p="${esc(f.name)}" data-n="${esc(display)}" onclick="wcDownloadDocument('${esc(caseId)}',this.dataset.p,this.dataset.n)">Download</button></span></div>`;
      }).join("") : '<span class="muted">No documents uploaded.</span>';
  return `${wcDocs.listError?`<div class="banner warn">${esc(wcDocs.listError)}</div>`:""}
    <div style="margin-top:4px">${docs}</div>
    <div class="legal-upload"><input id="wc-files" type="file" multiple aria-describedby="wc-staged-files wc-doc-status" onchange="wcSetFiles(this)"><button id="wc-upload-action" class="btn sm sec" aria-busy="${wcDocs.busy}" ${wcDocs.busy?'disabled':''} onclick="wcUploadDocuments('${esc(caseId)}')">${wcDocs.busy?'Uploading…':wcDocs.retry?'Retry failed files':'Upload'}</button></div>
    <div class="note-sm" id="wc-staged-files">${wcDocs.files.length?`${wcDocs.retry?'Retry queue (stored safely in this tab)':'Selected for upload'}: ${wcDocs.files.map(f=>esc(f.name)).join(", ")}`:""}</div>
    <p class="note-sm">Documents are private to the HR team and cannot be changed or deleted after upload. Download to view.</p>
    <div id="wc-doc-status" aria-live="polite">${wcDocs.status?`<div class="banner ok">${esc(wcDocs.status)}</div>`:""}${wcDocs.error?`<div class="banner err">${esc(wcDocs.error)}</div>`:""}</div>`;
}
function renderWcDocsBox(){
  const el=$("wc-docs-box");
  if (el && wcDocs.caseId) el.innerHTML=wcDocsBoxHtml(wcDocs.caseId);
}
async function loadWcDocuments(caseId){
  const ctx=wcDocsContext(caseId);
  const seq=++wcDocs.seq;
  const current=()=>ctx.sameIdentity() && seq===wcDocs.seq;
  const prefix=`wc/${caseId}`, pageSize=100, files=[];
  let listError="";
  for (let offset=0; ; offset+=pageSize){
    if (offset>=5000){ listError="More than 5,000 documents were found; narrow storage cleanup is required."; break; }
    const result = await sb.storage.from("evidence").list(prefix,{limit:pageSize,offset,sortBy:{column:"created_at",order:"desc"}});
    if (!current()) return;
    if (result.error){ listError=errText(result.error); break; }
    const page = result.data || [];
    files.push(...page);
    if (page.length < pageSize) break;
  }
  wcDocs.list=files; wcDocs.loaded=true; wcDocs.listError=listError;
  if (ctx.visible()) renderWcDocsBox();
}
function wcSetFiles(input){
  if (wcDocs.caseId!==wcSelected) return;
  wcDocs.files=Array.from(input?.files||[]); wcDocs.status=""; wcDocs.error=""; wcDocs.retry=false;
  // Patch in place — a #wc-docs-box repaint here would destroy the <input>
  // mid-onchange and clear its native chosen-file label. A new selection
  // replaces any retry queue (matching Legal), so the stale "Retry failed
  // files" label and old banners must reset with it.
  const staged=$("wc-staged-files");
  if (staged) staged.textContent=wcDocs.files.length?`Selected for upload: ${wcDocs.files.map(f=>f.name).join(", ")}`:"";
  const button=$("wc-upload-action");
  if (button && !wcDocs.busy) button.textContent="Upload";
  const status=$("wc-doc-status");
  if (status) status.innerHTML="";
}
function setWcDocsBusy(active){
  // Busy toggle patches only the button + status line: a full box repaint at
  // busy-start would recreate the file input and visibly clear its native
  // chosen-file label (mirrors setLegalActionBusy).
  const button=$("wc-upload-action");
  if (button){ button.disabled=active; button.setAttribute("aria-busy",String(active)); button.textContent=active?"Uploading…":(wcDocs.retry?"Retry failed files":"Upload"); }
  const status=$("wc-doc-status");
  if (active && status) status.innerHTML='<span class="note-sm">Uploading documents…</span>';
}
function finishWcUpload(ctx, failures, uploaded, paused=false){
  wcDocs.busy=false; wcDocs.retry=wcDocs.files.length>0;
  wcDocs.status=uploaded?`${uploaded} document${uploaded===1?"":"s"} uploaded successfully.`:"";
  const messages=[];
  if (failures.length) messages.push(`${failures.length} failed: ${failures.join("; ")}.`);
  if (paused && wcDocs.files.length) messages.push(`Upload paused after leaving Workers' Comp; ${wcDocs.files.length} file${wcDocs.files.length===1?" remains":"s remain"} in the retry queue.`);
  else if (failures.length) messages.push(`Select “Retry failed files” to retry only ${failures.length===1?"this file":"these files"}.`);
  wcDocs.error=messages.join(" ");
  if (ctx.visible()){ renderWcDocsBox(); if (uploaded) loadWcDocuments(wcDocs.caseId); }
}
async function wcUploadDocuments(caseId){
  if (wcDocs.busy || wcDocs.caseId!==caseId) return;
  const files=[...wcDocs.files];
  if (!files.length) return;
  const oversized=files.find(file=>file.size>25*1024*1024);
  if (oversized){ wcDocs.error=`${oversized.name} is larger than the 25 MB limit.`; wcDocs.status=""; wcDocs.retry=false; renderWcDocsBox(); return; }
  const ctx=wcDocsContext(caseId);
  wcDocs.busy=true; wcDocs.error=""; wcDocs.status=""; setWcDocsBusy(true);
  const failures=[];
  let uploaded=0;
  for (const file of files){
    if (!ctx.sameIdentity()) return;
    if (!ctx.visible()){ finishWcUpload(ctx,failures,uploaded,true); return; }
    const storedName = legalUploadName(file.name);
    const path = wcStoragePath(caseId,storedName);
    if (!path){ failures.push(`${file.name}: document name could not be prepared safely`); continue; }
    const { error } = await sb.storage.from("evidence").upload(path,file,{upsert:false,contentType:file.type||undefined});
    if (!ctx.sameIdentity()) return;
    if (error){ failures.push(`${file.name}: ${error.message||"unknown error"}`); continue; }
    uploaded += 1;
    wcDocs.files=wcDocs.files.filter(candidate=>candidate!==file);
    if (!ctx.visible()){ finishWcUpload(ctx,failures,uploaded,true); return; }
  }
  if (!ctx.sameIdentity()) return;
  finishWcUpload(ctx,failures,uploaded,false);
}
async function wcDownloadDocument(caseId, storedName, displayName){
  const path = wcStoragePath(caseId,storedName);
  if (!path){ alert("This document path is invalid."); return; }
  const ctx=wcDocsContext(caseId);
  const { data, error } = await sb.storage.from("evidence").download(path);
  if (!ctx.visible()) return;
  if (error || !data){ alert("Could not download this document: " + (error?.message||"unknown error")); return; }
  downloadBlob(data,displayName||legalDocumentName(storedName));
}
function wcOpen(id){ wcDocs=blankWcDocs(id!=="new"?id:null); wcSelected = id; render(); syncRoute(); if (id!=="new") loadWcDocuments(id); window.scrollTo({top:0,behavior:"smooth"}); }
function wcClose(){ wcDocs=blankWcDocs(); wcSelected = null; render(); syncRoute(); }
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
  const { data, error } = await sb.rpc("wc_save", { p_id: wcSelected === "new" ? null : wcSelected, p });
  if (error){ err(errText(error)); return; }
  // A freshly created claim reopens in the editor so documents can be attached
  // immediately instead of hunting for the new row in the list (QC 9/16).
  if (wcSelected === "new" && data?.id){ wcOpen(data.id); return; }
  wcDocs = blankWcDocs(); wcSelected = null; render(); syncRoute();
}

// ---------- LEGAL & CLAIMS TRACKER (source workbook spec, 8/18) -----------
// Structural sibling of the Workers' Comp tab: legal_cases table + legal_save
// RPC (migration 018), module-state filters, noon-anchored date-only rendering.
// "Overdue" = due_date <= today (start-of-day compare) on an Active case.
const lgDue = r => r.case_state === "Active" && r.due_date
  && new Date(String(r.due_date).slice(0,10)+"T00:00:00") <= new Date();
const lgStatusPill = s => !s ? '<span class="muted">—</span>'
  : `<span class="pill ${s==="Litigation"?"due-over":s==="Settlement Reached"?"due-ok":"dot"}">${esc(s)}</span>`;
// Currency display for the T137 financial fields. Off-list junk (shouldn't
// happen — the DB column is numeric) falls back to the raw escaped string.
const fmtMoney = v => {
  if (v === null || v === undefined || v === "") return "";
  const n = Number(v);
  return Number.isFinite(n) ? n.toLocaleString("en-US",{style:"currency",currency:"USD"}) : String(v);
};
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
let lgSort = { key:"", dir:1 };
const LG_SORT_VALS = {
  ref: r => r.ref || "",
  risk: r => ({High:0,Medium:1,Low:2}[r.risk_level] ?? 3),
  status: r => r.status || "",
  complainant: r => r.complainant || "",
  type: r => r.claim_type || "",
  opposing: r => r.opposing_counsel || "",
  company: r => r.company_counsel || "",
  ebpoint: r => r.eb_point || "",
  due: r => Date.parse(r.due_date || "") || 0,
};
const LG_COLUMNS = [["ref","Case ID"],["risk","Risk"],["status","Status"],["complainant","Complainant"],["type","Type"],["opposing","Opposing counsel / agency"],["company","Company counsel"],["ebpoint","EB point"],["due","Due date"],["","Docs"]];
function setLegalSort(key){
  if (!LG_SORT_VALS[key]) return;
  if (lgSort.key === key) lgSort.dir = -lgSort.dir;
  else lgSort = { key, dir:1 };
  updateLegalResults();
}
function legalModel(){
  const q = lgFilters.q.trim().toLowerCase();
  const shown = legalData.filter(r =>
    (!lgFilters.state  || r.case_state === lgFilters.state) &&
    (!lgFilters.risk   || r.risk_level === lgFilters.risk) &&
    (!lgFilters.status || r.status === lgFilters.status) &&
    (!lgFilters.type   || r.claim_type === lgFilters.type) &&
    (!lgFilters.quick ||
      (lgFilters.quick === "active" && r.case_state === "Active") ||
      (lgFilters.quick === "high" && r.case_state === "Active" && r.risk_level === "High") ||
      (lgFilters.quick === "litigation" && r.case_state === "Active" && r.status === "Litigation") ||
      (lgFilters.quick === "due" && lgDue(r))) &&
    (!q || [r.ref, r.complainant, r.opposing_counsel, r.company_counsel, r.eb_point,
      r.synopsis, r.pending_action, r.epli_notes, r.notes, r.violation_description].some(v => (v||"").toLowerCase().includes(q))));
  if (lgSort.key && LG_SORT_VALS[lgSort.key]) shown.sort(trackerCompare(lgSort, LG_SORT_VALS));
  return { rows:legalData, shown };
}
function legalRowsHtml({shown}){
  return shown.length ? shown.map(r=>`<tr class="clk ${lgDue(r)?'overdue':''}" onclick="lgOpen('${esc(r.id)}')">
    <td style="padding-left:20px"><button type="button" class="row-link ref" aria-label="Open legal case ${esc(r.ref)}" onclick="event.stopPropagation();lgOpen('${esc(r.id)}')">${esc(r.ref)}</button>${r.case_state==='Completed'?' <span class="chip">Completed</span>':''}</td>
    <td>${riskPill(r.risk_level)}</td><td>${lgStatusPill(r.status)}</td><td>${esc(r.complainant||'—')}</td>
    <td>${esc(r.claim_type||'—')}</td><td>${esc(r.opposing_counsel||'—')}</td><td>${esc(r.company_counsel||'—')}</td><td>${esc(r.eb_point||'—')}</td>
    <td>${r.due_date ? (lgDue(r)?`<span class="pill due-over">${fmtDateOnly(r.due_date)}</span>`:fmtDateOnly(r.due_date)) : (r.due_date_note?`<span class="muted">${esc(r.due_date_note)}</span>`:'—')}</td>
    <td onclick="event.stopPropagation()">${lgDocsCell(r.docs_link)}</td>
  </tr>`).join("") : `<tr><td colspan="10" class="empty-row">No legal cases match these filters.</td></tr>`;
}
function legalFilterChipsHtml(){
  const quick = {active:"Active cases",high:"High risk",litigation:"In litigation",due:"Due follow-ups"};
  const entries = [];
  if (lgFilters.quick) entries.push({key:"quick",label:quick[lgFilters.quick]});
  if (lgFilters.q.trim()) entries.push({key:"q",label:`Search: “${lgFilters.q.trim()}”`});
  if (lgFilters.state) entries.push({key:"state",label:`Case state: ${lgFilters.state}`});
  if (lgFilters.risk) entries.push({key:"risk",label:`Risk: ${lgFilters.risk}`});
  if (lgFilters.status) entries.push({key:"status",label:`Status: ${lgFilters.status}`});
  if (lgFilters.type) entries.push({key:"type",label:`Type: ${lgFilters.type}`});
  return trackerChipsHtml(entries,"clearLegalFilter");
}
function syncLegalFilterInputs(){
  [["lg-q","q"],["lg-f-state","state"],["lg-f-risk","risk"],["lg-f-status","status"],["lg-f-type","type"]].forEach(([id,key])=>{ if ($(id)) $(id).value=lgFilters[key]; });
}
function updateLegalResults(){
  const model = legalModel();
  patchTrackerHead("legal-table-head", lgSort);
  if ($("legal-table-body")) $("legal-table-body").innerHTML = legalRowsHtml(model);
  if ($("legal-result-count")) $("legal-result-count").textContent = `Showing ${model.shown.length} of ${model.rows.length} legal cases`;
  if ($("legal-active-filters")) $("legal-active-filters").innerHTML = legalFilterChipsHtml();
  document.querySelectorAll("[data-legal-quick-filter]").forEach(tile=>{
    const active = lgFilters.quick === tile.dataset.legalQuickFilter;
    tile.classList.toggle("active",active); tile.setAttribute("aria-pressed",String(active));
  });
}
// Like the primary dashboard, these filters repaint cached rows without
// re-querying Supabase or disturbing an open editor.
function lgApplyFilters(){
  lgFilters.q      = $("lg-q")?.value        ?? lgFilters.q;
  lgFilters.state  = $("lg-f-state")?.value  ?? lgFilters.state;
  lgFilters.risk   = $("lg-f-risk")?.value   ?? lgFilters.risk;
  lgFilters.status = $("lg-f-status")?.value ?? lgFilters.status;
  lgFilters.type   = $("lg-f-type")?.value   ?? lgFilters.type;
  updateLegalResults();
}
function setLegalQuickFilter(kind){ lgFilters.quick = lgFilters.quick === kind ? "" : kind; updateLegalResults(); }
function clearLegalFilter(key){ if (!(key in lgFilters)) return; lgFilters[key]=""; syncLegalFilterInputs(); updateLegalResults(); }
function clearLegalFilters(){ lgFilters={q:"",state:"",risk:"",status:"",type:"",quick:""}; syncLegalFilterInputs(); updateLegalResults(); }
async function renderLegalInto(el){
  const epoch = sessionEpoch;
  const dv = dashView;                       // stale-paint guard (QC 8/31)
  const userId = session?.user?.id;
  const { data:list, error } = await sb.from("legal_cases").select("*").order("ref");
  if (epoch !== sessionEpoch || dashView !== dv || !el.isConnected) return;  // view/session changed while loading
  if (error){
    const msg = /does not exist|schema cache|PGRST/i.test(error.message||"")
      ? "The Legal & Claims backend (migration 018) isn't deployed yet." : error.message;
    el.innerHTML = `<div class="card"><div class="banner err">${esc(msg)}</div></div>`; return;
  }
  legalData = list || [];
  const rows = legalData;
  // Stat tiles are scoped to ACTIVE cases — a completed matter's risk or old
  // "Litigation" status shouldn't inflate the live picture.
  const act = rows.filter(r => r.case_state === "Active");
  const activeN = act.length;
  const hiN = act.filter(r => r.risk_level === "High").length;
  const litN = act.filter(r => r.status === "Litigation").length;
  const dueN = rows.filter(lgDue).length;
  const model = legalModel();
  // Off-list stored values (free-ish columns) must still be offered as filter options.
  const statusOpts = [...new Set([...LEGAL_STATUSES, ...rows.map(r=>r.status)])].filter(Boolean);
  const typeOpts   = [...new Set([...LEGAL_TYPES,    ...rows.map(r=>r.claim_type)])].filter(Boolean);
  // A stale selection (row no longer present) must not render as a "new" form —
  // saving it would target the missing id. Drop back to the list instead.
  if (lgSelected && lgSelected !== "new" && !rows.some(r => r.id === lgSelected)) lgSelected = null;
  const sel = lgSelected && lgSelected !== "new" ? rows.find(r => r.id === lgSelected) : null;
  if (sel) {
    const stillCurrent = () => epoch === sessionEpoch && session?.user?.id === userId
      && dashView === dv && lgSelected === sel.id && el.isConnected;
    const [notesResult, filesResult, linksResult] = await Promise.all([
      sb.from("legal_case_notes").select("*").eq("legal_case_id",sel.id).order("created_at",{ascending:true}),
      listLegalDocuments(sel.id, stillCurrent),
      sb.from("legal_case_links").select("*").eq("legal_case_id",sel.id).order("created_at",{ascending:true}),
    ]);
    if (!stillCurrent() || filesResult.stale) return;
    // T137 linked cases: fetch the linked case rows the viewer is allowed to
    // see (RLS/can_see_case filters silently) and each visible case's ordinary
    // file surfaces. A link whose case stays invisible renders from linked_ref only.
    const links = linksResult.data || [];
    const linkedCases = {}, linkedFiles = {};
    if (links.length){
      const ids = links.map(l=>l.linked_case_id);
      const { data: visibleCases } = await sb.from("cases").select("id,ref,intake_type,category,state,created_at").in("id",ids);
      if (!stillCurrent()) return;
      for (const c of visibleCases || []) linkedCases[c.id] = c;
      await Promise.all(links.filter(l=>linkedCases[l.linked_case_id]).map(async l=>{
        const result = await listLinkedCaseDocuments(l.linked_case_id, stillCurrent);
        if (!result.stale) linkedFiles[l.linked_case_id] = result;
      }));
      if (!stillCurrent()) return;
    }
    legalDetail = {
      notes: notesResult.data || [],
      files: filesResult.data || [],
      links, linkedCases, linkedFiles,
      errors: [notesResult.error ? "HR notes are unavailable until the Legal Claims detail migration is deployed." : "",
               filesResult.error ? "Related document storage is not available yet." : "",
               linksResult.error ? "Linked cases are unavailable until the T137 legal migration is deployed." : ""].filter(Boolean),
    };
  } else {
    legalDetail = { notes:[], files:[], links:[], linkedCases:{}, linkedFiles:{}, errors:[] };
  }
  if (lgSelected) {
    el.innerHTML = lgSelected === "new" || lgEditing ? lgEditor(sel) : lgSummary(sel);
    if (legalPreview.open) {
      const generation = legalPreviewGeneration;
      requestAnimationFrame(() => {
        if (!legalPreview.open || generation !== legalPreviewGeneration || view !== "dashboard" || dashView !== "legal" || !document.querySelector(".legal-preview-modal")) return;
        setLegalPreviewBackgroundInert(true);
        $("lg-preview-close")?.focus();
      });
    }
    else if (legalPreviewRestoreName) requestAnimationFrame(() => {
      const name=legalPreviewRestoreName; legalPreviewRestoreName="";
      [...document.querySelectorAll("button[data-p]")].find(button=>button.dataset.p===name)?.focus();
    });
    return;
  }
  el.innerHTML = `<div class="card">
      <div style="display:flex;align-items:center;gap:16px;flex-wrap:wrap">
        <h2 class="section" style="margin:0">HR dashboard</h2>
        <div class="dash-toggle">
          <button aria-pressed="false" onclick="setDashView('cases')">Cases</button>
          <button aria-pressed="false" onclick="setDashView('requests')">Requests</button>
          <button aria-pressed="false" onclick="setDashView('closed')">Closed</button>
          <button aria-pressed="false" onclick="setDashView('wc')">Workers' Comp</button>
          <button class="on" aria-pressed="true" onclick="setDashView('legal')">Legal &amp; Claims</button>
        </div>
      </div>
      <div class="row dashboard-stats" style="margin:18px 0 4px">
        <button type="button" class="stat stat-button ${lgFilters.quick==='active'?'active':''}" data-legal-quick-filter="active" aria-pressed="${lgFilters.quick==='active'}" onclick="setLegalQuickFilter('active')"><div class="n">${activeN}</div><div class="l">Active cases</div><div class="stat-hint">Filter table</div></button>
        <button type="button" class="stat stat-button ${lgFilters.quick==='high'?'active':''}" data-legal-quick-filter="high" aria-pressed="${lgFilters.quick==='high'}" onclick="setLegalQuickFilter('high')"><div class="n" style="color:${hiN?'var(--danger)':'var(--ok)'}">${hiN}</div><div class="l">High risk</div><div class="stat-hint">Filter table</div></button>
        <button type="button" class="stat stat-button ${lgFilters.quick==='litigation'?'active':''}" data-legal-quick-filter="litigation" aria-pressed="${lgFilters.quick==='litigation'}" onclick="setLegalQuickFilter('litigation')"><div class="n" style="color:${litN?'var(--danger)':'var(--ok)'}">${litN}</div><div class="l">In litigation</div><div class="stat-hint">Filter table</div></button>
        <button type="button" class="stat stat-button ${lgFilters.quick==='due'?'active':''}" data-legal-quick-filter="due" aria-pressed="${lgFilters.quick==='due'}" onclick="setLegalQuickFilter('due')"><div class="n" style="color:${dueN?'var(--warn)':'var(--ok)'}">${dueN}</div><div class="l">Due follow-ups</div><div class="stat-hint">Filter table</div></button>
      </div>
      <div class="rule"></div>
      <div class="filter-panel-head tracker-filter-head"><div><b>Filter legal cases</b><div id="legal-result-count" class="note-sm">Showing ${model.shown.length} of ${model.rows.length} legal cases</div></div><button class="btn sm sec" onclick="lgOpen('new')">+ New case</button></div>
      <div class="filter-grid tracker-filter-grid">
        <label class="filter-field filter-search"><span>Search</span><input id="lg-q" type="text" placeholder="Ref, complainant, counsel, synopsis…" value="${esc(lgFilters.q)}" oninput="lgApplyFilters()"></label>
        <label class="filter-field"><span>Case state</span><select id="lg-f-state" onchange="lgApplyFilters()"><option value="">All states</option>${LEGAL_STATES.map(s=>`<option ${lgFilters.state===s?'selected':''}>${s}</option>`).join("")}</select></label>
        <label class="filter-field"><span>Risk</span><select id="lg-f-risk" onchange="lgApplyFilters()"><option value="">All risks</option>${RISKS.map(r=>`<option ${lgFilters.risk===r?'selected':''}>${r}</option>`).join("")}</select></label>
        <label class="filter-field"><span>Status</span><select id="lg-f-status" onchange="lgApplyFilters()"><option value="">All statuses</option>${statusOpts.map(s=>`<option ${lgFilters.status===s?'selected':''}>${esc(s)}</option>`).join("")}</select></label>
        <label class="filter-field"><span>Type</span><select id="lg-f-type" onchange="lgApplyFilters()"><option value="">All types</option>${typeOpts.map(t=>`<option ${lgFilters.type===t?'selected':''}>${esc(t)}</option>`).join("")}</select></label>
      </div>
      <div id="legal-active-filters" class="active-filter-list" aria-live="polite">${legalFilterChipsHtml()}</div>
    </div>
    <div class="card" style="padding:8px 0;overflow-x:auto"><table>
      <thead><tr id="legal-table-head">${trackerHeadHtml(LG_COLUMNS, lgSort, "setLegalSort")}</tr></thead>
      <tbody id="legal-table-body">${legalRowsHtml(model)}</tbody>
    </table></div>`;
}
const legalDocumentName = name => String(name||"").replace(/^[0-9a-f-]{36}_/i,"");
async function listLegalDocuments(caseId, isCurrent=()=>true){
  const prefix = `legal/${caseId}`;
  const pageSize = 100;
  const files = [];
  for (let offset=0; offset<5000; offset+=pageSize){
    const result = await sb.storage.from("evidence").list(prefix,{limit:pageSize,offset,sortBy:{column:"created_at",order:"desc"}});
    if (!isCurrent()) return {data:[],error:null,stale:true};
    if (result.error) return {...result,stale:false};
    const page = result.data || [];
    files.push(...page);
    if (page.length < pageSize) return {data:files,error:null,stale:false};
  }
  return {data:files,error:{message:"More than 5,000 legal documents were found; narrow storage cleanup is required."},stale:false};
}
const LINKED_DOCUMENT_PAGE_SIZE = 100;
const LINKED_DOCUMENT_MAX_ROWS = 5000;
async function listLinkedEvidence(caseId, isCurrent=()=>true){
  const files = [], seen = new Set();
  for (let offset=0; offset<LINKED_DOCUMENT_MAX_ROWS; offset+=LINKED_DOCUMENT_PAGE_SIZE){
    // Name is immutable for these append-only objects and gives offset paging
    // a deterministic order even when created_at values tie.
    const result = await sb.storage.from("evidence").list(caseId,{limit:LINKED_DOCUMENT_PAGE_SIZE,offset,sortBy:{column:"name",order:"asc"}});
    if (!isCurrent()) return {data:[],error:null,stale:true};
    if (result.error) return {data:files,error:result.error,stale:false};
    const page = result.data || [];
    for (const file of page) if (file?.name && !seen.has(file.name)){seen.add(file.name);files.push(file);}
    if (page.length < LINKED_DOCUMENT_PAGE_SIZE) return {data:files,error:null,stale:false};
  }
  return {data:files,error:{message:"More than 5,000 evidence files were found."},stale:false};
}
async function listLinkedCaseFiles(caseId, isCurrent=()=>true){
  const files = [], seen = new Set();
  for (let offset=0; offset<LINKED_DOCUMENT_MAX_ROWS; offset+=LINKED_DOCUMENT_PAGE_SIZE){
    const result = await sb.from("case_files")
      .select("id,case_id,source,file_name,mime_type,size_bytes,storage_path,email_fallback_url,uploaded_by,created_at")
      .eq("case_id",caseId).order("created_at",{ascending:false}).order("id",{ascending:false})
      .range(offset,offset+LINKED_DOCUMENT_PAGE_SIZE-1);
    if (!isCurrent()) return {data:[],error:null,stale:true};
    if (result.error) return {data:files,error:result.error,stale:false};
    const page = result.data || [];
    for (const file of page) if (file?.id && !seen.has(file.id)){seen.add(file.id);files.push(file);}
    if (page.length < LINKED_DOCUMENT_PAGE_SIZE) return {data:files,error:null,stale:false};
  }
  return {data:files,error:{message:"More than 5,000 case-file attachments were found."},stale:false};
}
async function listLinkedMessageFiles(caseId, isCurrent=()=>true){
  const result = await messageAttachmentAction({action:"list",mode:"handler",caseId});
  if (!isCurrent()) return {data:[],error:null,stale:true};
  if (result.error) return {data:[],error:result.error,stale:false};
  const files = [], seen = new Set();
  for (const message of result.data?.messages || []) for (const file of message.attachments || []) {
    if (file?.id && !seen.has(file.id)){seen.add(file.id);files.push({...file,messageId:message.id,messageAt:message.at,sender:message.sender});}
  }
  return {data:files,error:null,stale:false};
}
async function listLinkedCaseDocuments(caseId, isCurrent=()=>true){
  // Each source keeps its existing authorization boundary: Storage policies
  // for ordinary/email evidence, case_files RLS, and the conflict-aware
  // message-attachments Edge authorization. The restricted medical bucket is
  // deliberately never queried by this ordinary Legal surface.
  const [evidenceResult,caseFilesResult,messageFilesResult] = await Promise.all([
    listLinkedEvidence(caseId,isCurrent),
    listLinkedCaseFiles(caseId,isCurrent),
    listLinkedMessageFiles(caseId,isCurrent),
  ]);
  if (!isCurrent() || evidenceResult.stale || caseFilesResult.stale || messageFilesResult.stale) {
    return {evidence:[],caseFiles:[],messageFiles:[],errors:[],stale:true};
  }
  return {
    evidence:evidenceResult.data || [], caseFiles:caseFilesResult.data || [], messageFiles:messageFilesResult.data || [],
    errors:[evidenceResult.error?"Ordinary evidence could not be loaded.":"",
      caseFilesResult.error?"Email and case-file attachments could not be loaded.":"",
      messageFilesResult.error?"Message attachments could not be loaded.":""].filter(Boolean),
    stale:false,
  };
}
const legalDocumentKind = name => {
  const ext = String(name||"").split(".").pop().toLowerCase();
  if (["png","jpg","jpeg","gif","webp"].includes(ext)) return "image";
  if (["pdf","txt","csv"].includes(ext)) return "frame";
  return "download";
};
function lgSummary(r){
  if (!r) return "";
  if (legalComposer.caseId !== r.id) legalComposer = {caseId:r.id,note:"",files:[],status:"",error:"",noteError:"",retry:false};
  const docs = legalDetail.files.length ? legalDetail.files.map(f=>{
    const display = legalDocumentName(f.name);
    const kind = legalDocumentKind(display);
    return `<div class="task"><span><b>${esc(display)}</b><span class="muted" style="font-size:11px"> · ${fmtBytes(f.metadata?.size)}${f.created_at?` · ${fmt(f.created_at)}`:""}</span></span>
      <span style="margin-left:auto;display:flex;gap:6px;flex-wrap:wrap">
        ${kind!=="download"?`<button class="btn sm sec" data-p="${esc(f.name)}" data-n="${esc(display)}" onclick="lgPreviewDocument('${esc(r.id)}',this.dataset.p,this.dataset.n)">Preview</button>`:""}
        <button class="btn sm ghost" data-p="${esc(f.name)}" data-n="${esc(display)}" onclick="lgDownloadDocument('${esc(r.id)}',this.dataset.p,this.dataset.n)">Download</button>
      </span></div>`;
  }).join("") : '<span class="muted">No related documents uploaded.</span>';
  return `<button class="back" onclick="lgClose()">← Back to legal cases</button>
    <div class="card legal-summary">
      <div class="legal-summary-head"><div><span class="ref" style="font-size:16px">${esc(r.ref)}</span> ${lgStatusPill(r.status)} ${riskPill(r.risk_level)} ${r.case_state==='Completed'?'<span class="chip">Completed</span>':''}</div>
        <button class="btn sm ghost" onclick="lgEdit()">Edit details</button></div>
      <h2 class="section">${esc(r.complainant || r.claim_type || "Legal / claims case")}</h2>
      <div class="row">
        <div class="col">
          <div class="kv"><span class="k">Complainant</span><b>${esc(r.complainant||'—')}</b></div>
          <div class="kv"><span class="k">Type</span><span>${esc(r.claim_type||'—')}</span></div>
          <div class="kv"><span class="k">Case state</span><span>${esc(r.case_state||'—')}</span></div>
          <div class="kv"><span class="k">Due date</span><span class="${lgDue(r)?'pill due-over':''}">${r.due_date?esc(fmtDateOnly(r.due_date)):'—'}</span></div>
          <div class="kv"><span class="k">Due date note</span><span>${esc(r.due_date_note||'—')}</span></div>
        </div>
        <div class="col">
          <div class="kv"><span class="k">Opposing side</span><span>${esc(r.opposing_counsel||'—')}</span></div>
          <div class="kv"><span class="k">Company counsel</span><span>${esc(r.company_counsel||'—')}</span></div>
          <div class="kv"><span class="k">EB point</span><span>${esc(r.eb_point||'—')}</span></div>
          <div class="kv"><span class="k">EPLI tendered</span><span>${esc(r.epli_tendered||'—')}</span></div>
          <div class="kv"><span class="k">Settlement amount</span><span>${fmtMoney(r.settlement_amount)?`<b>${esc(fmtMoney(r.settlement_amount))}</b> <span class="muted" style="font-size:11px">agreed</span>`:'—'}</span></div>
          <div class="kv"><span class="k">Penalty amount</span><span>${fmtMoney(r.penalty_amount)?`<b>${esc(fmtMoney(r.penalty_amount))}</b> <span class="muted" style="font-size:11px">court-ordered</span>`:'—'}</span></div>
        </div>
      </div>
      <div class="divider"></div>
      <div class="mini-l">Synopsis</div><div class="banner desc">${esc(r.synopsis||'No synopsis recorded.')}</div>
      <div class="grid2 legal-summary-notes">
        <div><div class="mini-l">Pending action</div><div class="detail-copy">${esc(r.pending_action||'—')}</div></div>
        <div><div class="mini-l">EPLI coverage notes</div><div class="detail-copy">${esc(r.epli_notes||'—')}</div></div>
        <div><div class="mini-l">Violation description</div><div class="detail-copy">${esc(r.violation_description||'—')}</div></div>
      </div>
    </div>
    ${legalDetail.errors.map(m=>`<div class="banner warn">${esc(m)}</div>`).join("")}
    <div class="row legal-detail-row">
      <div class="col card"><div class="legal-section-head"><b>HR notes</b><span class="chip">internal · append-only</span></div>
        <div style="margin-top:12px">${legalDetail.notes.length?legalDetail.notes.map(n=>{const person=dirList.find(d=>(d.email||"").toLowerCase()===(n.author_email||"").toLowerCase());return `<div class="hrnote"><div class="t">${esc(person?.name||n.author_email||'HR')} · ${fmt(n.created_at)}</div>${esc(n.body)}</div>`;}).join(""):'<span class="muted">No HR notes yet.</span>'}</div>
        <div class="legal-note-compose"><textarea id="lg-hr-note" placeholder="Add an internal note…" rows="3" oninput="lgSetNoteDraft(this.value)">${esc(legalComposer.note)}</textarea><button id="lg-note-action" class="btn sec" aria-busy="${legalBusy.note}" ${legalBusy.note?'disabled':''} onclick="lgAddNote('${esc(r.id)}')">${legalBusy.note?'Adding…':'Add note'}</button></div>
        <div id="lg-note-status" aria-live="polite">${legalComposer.noteError?`<div class="banner err">${esc(legalComposer.noteError)}</div>`:""}</div>
      </div>
      <div class="col card"><div class="legal-section-head"><b>Related documents</b><span class="chip">private</span></div>
        ${r.docs_link?`<div class="kv"><span class="k">Existing folder</span><span>${lgDocsCell(r.docs_link)}</span></div>`:""}
        <div style="margin-top:12px">${docs}</div>
        <div class="legal-upload"><input id="lg-files" type="file" multiple aria-describedby="lg-staged-files lg-doc-status" onchange="lgSetFiles(this)"><button id="lg-upload-action" class="btn sm sec" aria-busy="${legalBusy.upload}" ${legalBusy.upload?'disabled':''} onclick="lgUploadDocuments('${esc(r.id)}')">${legalBusy.upload?'Uploading…':legalComposer.retry?'Retry failed files':'Upload'}</button></div>
        <div class="note-sm" id="lg-staged-files">${legalComposer.files.length?`${legalComposer.retry?'Retry queue (stored safely in this tab)':'Selected for upload'}: ${legalComposer.files.map(f=>esc(f.name)).join(", ")}`:""}</div>
        <p class="note-sm">PDFs, images, text, and CSV files preview here. Other file types remain available to download.</p>
        <div id="lg-doc-status" aria-live="polite">${legalComposer.status?`<div class="banner ok">${esc(legalComposer.status)}</div>`:""}${legalComposer.error?`<div class="banner err">${esc(legalComposer.error)}</div>`:""}</div>
      </div>
    </div>
    ${lgLinkedCasesCard(r)}
    ${legalPreview.open?lgPreviewModal():""}`;
}
// ---- T137 linked cases -----------------------------------------------------
// A legal case can link other cases (incident cases AND accommodation
// requests — both live in the cases table) by case-number search. Ordinary
// evidence and attachments automatically appear here, read through the
// EXISTING Storage/RLS/Edge authorization paths: a viewer only sees files of
// cases they could already open (conflict blinding intact). Medical-vault
// content is intentionally excluded. Case deletion no longer exists in
// the UI (8/18: no deletes), so the "deleting removes its evidence from the
// legal view" warning lives on the Unlink action instead.
// INTENTIONAL: this card renders from lgSummary() ONLY, never from lgEditor().
// The link search repaints (#lg-link-results) and the render() after
// link/unlink must stay away from a form full of unsaved field edits. The
// legal_links harness scene asserts the card is ABSENT in edit mode — keep it
// that way (or add a wipe-guard first) if the editor ever grows this card.
function lgLinkedCasesCard(r){
  const links = legalDetail.links || [];
  const rows = links.length ? links.map(l=>{
    const c = legalDetail.linkedCases[l.linked_case_id];
    const carried = legalDetail.linkedFiles[l.linked_case_id] || {evidence:[],caseFiles:[],messageFiles:[],errors:[]};
    const evidenceRows = (carried.evidence||[]).map(f=>{
      // Case evidence names carry either a uuid_ or a timestamp_ uniqueness
      // prefix (uploadEvidenceFile vs its non-crypto fallback) — strip both.
      const display = legalDocumentName(f.name).replace(/^\d+_/,'');
      const kind = attachmentKind(display, f.metadata?.mimetype||"");
      return `<div class="task"><span><b>${esc(display)}</b><span class="muted" style="font-size:11px"> · ${fmtBytes(f.metadata?.size)}${f.created_at?` · ${fmt(f.created_at)}`:""}</span></span>
        <span style="margin-left:auto;display:flex;gap:6px;flex-wrap:wrap">
          ${kind!=="download"?`<button class="btn sm sec" data-c="${esc(l.linked_case_id)}" data-p="${esc(f.name)}" data-n="${esc(display)}" onclick="lgLinkedEvidencePreview(this.dataset.c,this.dataset.p,this.dataset.n)">Preview</button>`:""}
          <button class="btn sm ghost" data-c="${esc(l.linked_case_id)}" data-p="${esc(f.name)}" onclick="lgLinkedEvidenceDownload(this.dataset.c,this.dataset.p)">Download</button>
        </span></div>`;
    }).join("");
    const caseFileRows = (carried.caseFiles||[]).map(f=>{
      const kind=attachmentKind(f.file_name,f.mime_type||"");
      const stored=f.storage_path && caseFilePathAllowed(f,l.linked_case_id);
      const actions=stored
        ? `<span style="margin-left:auto;display:flex;gap:6px;flex-wrap:wrap">${kind!=="download"?`<button class="btn sm sec" data-c="${esc(l.linked_case_id)}" data-p="${esc(f.storage_path)}" data-n="${esc(f.file_name)}" data-t="${esc(f.mime_type||'')}" onclick="lgLinkedCaseFilePreview(this.dataset.c,this.dataset.p,this.dataset.n,this.dataset.t,this.id)">Preview</button>`:""}<button class="btn sm ghost" data-c="${esc(l.linked_case_id)}" data-p="${esc(f.storage_path)}" data-n="${esc(f.file_name)}" onclick="lgLinkedCaseFileDownload(this.dataset.c,this.dataset.p,this.dataset.n)">Download</button></span>`
        : f.email_fallback_url?.startsWith("https://")
          ? `<a class="btn sm ghost" href="${esc(f.email_fallback_url)}" target="_blank" rel="noopener noreferrer">Open in mailbox</a>`
          : '<span class="muted" style="font-size:11px">stored in mailbox</span>';
      return `<div class="task"><span><b>${esc(f.file_name)}</b><span class="muted" style="font-size:11px"> · ${fmtBytes(f.size_bytes)}${f.created_at?` · ${fmt(f.created_at)}`:""}</span></span>${actions}</div>`;
    }).join("");
    const messageRows = (carried.messageFiles||[]).map(f=>{
      const kind=attachmentKind(f.name,f.type||"");
      return `<div class="task"><span><b>${esc(f.name)}</b><span class="muted" style="font-size:11px"> · ${fmtBytes(f.size)}${f.messageAt?` · ${fmt(f.messageAt)}`:""}</span></span><span style="margin-left:auto;display:flex;gap:6px;flex-wrap:wrap">${kind!=="download"?`<button id="lg-message-preview-${esc(f.id)}" class="btn sm sec" data-c="${esc(l.linked_case_id)}" data-i="${esc(f.id)}" data-n="${esc(f.name)}" data-t="${esc(f.type||'')}" onclick="lgLinkedMessagePreview(this.dataset.c,this.dataset.i,this.dataset.n,this.dataset.t,this.id)">Preview</button>`:""}<button class="btn sm ghost" data-c="${esc(l.linked_case_id)}" data-i="${esc(f.id)}" data-n="${esc(f.name)}" onclick="lgLinkedMessageDownload(this.dataset.c,this.dataset.i,this.dataset.n)">Download</button></span></div>`;
    }).join("");
    const fileSections = [
      evidenceRows?`<div class="mini-l">Evidence</div>${evidenceRows}`:"",
      caseFileRows?`<div class="mini-l" style="margin-top:10px">Email and case files</div>${caseFileRows}`:"",
      messageRows?`<div class="mini-l" style="margin-top:10px">Message attachments</div>${messageRows}`:"",
    ].filter(Boolean).join("");
    const emptyFiles = (carried.errors||[]).length
      ? '<span class="muted">No authorized files were returned from the attachment surfaces that loaded successfully.</span>'
      : '<span class="muted">No authorized ordinary evidence or attachments are available for this case.</span>';
    return `<div class="hrnote">
      <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap">
        <span class="ref">${esc(c?.ref || l.linked_ref)}</span>
        ${c?`<span class="chip">${esc(c.intake_type==="request"?"Accommodation / request":"Incident case")}</span> <span>${esc(c.category||"")}</span> <span class="muted">${esc(stlabel(c.state||""))}</span>`
           :`<span class="muted">Details restricted — this case isn't visible to you, so its files stay hidden.</span>`}
        <button class="btn sm ghost" style="margin-left:auto" data-l="${esc(l.id)}" data-r="${esc(c?.ref || l.linked_ref)}" onclick="lgUnlinkCase(this.dataset.l,this.dataset.r)">Unlink</button>
      </div>
      ${c?`<div style="margin-top:8px">${(carried.errors||[]).map(error=>`<div class="banner warn">${esc(error)}</div>`).join("")}${fileSections || emptyFiles}</div>`:""}
    </div>`;
  }).join("") : '<span class="muted">No linked cases.</span>';
  return `<div class="card" id="lg-linked-cases">
    <div class="legal-section-head"><b>Linked cases</b><span class="chip">ordinary files carry into this view</span></div>
    <p class="note-sm">Ordinary evidence, email/case files, and message attachments from a linked case appear below. Restricted medical-vault documents never carry into Legal. Unlinking removes these files from this view; the case and files themselves are not deleted.</p>
    <div style="margin-top:12px">${rows}</div>
    <div class="legal-note-compose" style="align-items:flex-end">
      <div style="flex:1"><label>Link a case by case number</label>
        <input id="lg-link-q" type="text" autocomplete="off" placeholder="e.g. EB-2026-0142 — incidents and accommodation requests" value="${esc(legalLinkPicker.query)}" oninput="lgLinkSearchInput(this.value)"></div>
    </div>
    <div id="lg-link-results" aria-live="polite" style="margin-top:8px;display:flex;gap:6px;flex-wrap:wrap">${lgLinkResultsHtml()}</div>
  </div>`;
}
function lgLinkResultsHtml(){
  if (legalLinkPicker.err) return `<div class="banner err">${esc(legalLinkPicker.err)}</div>`;
  if (!legalLinkPicker.query.trim() || legalLinkPicker.query.trim().length < 2) return "";
  if (legalLinkPicker.busy) return `<span class="note-sm">Searching…</span>`;
  // A match that only got filtered out because it is ALREADY linked must not
  // read as "no such case" — show it as an inert "Already linked" chip.
  const linked = legalLinkPicker.linked || [];
  if (!legalLinkPicker.results.length && !linked.length) return `<span class="note-sm">No matching cases you can access.</span>`;
  return legalLinkPicker.results.map(c=>`<button type="button" class="btn sm sec" data-c="${esc(c.id)}" onclick="lgLinkCase(this.dataset.c)">${esc(c.ref)} · ${esc(c.intake_type==="request"?"Request":"Incident")}${c.category?` · ${esc(c.category)}`:""} <span class="muted">${esc(stlabel(c.state||""))}</span></button>`).join("")
    + linked.map(c=>`<span class="chip">${esc(c.ref)} · Already linked</span>`).join("");
}
function paintLinkResults(){ const el=$("lg-link-results"); if (el) el.innerHTML = lgLinkResultsHtml(); }
function lgLinkSearchInput(value){
  if (!lgSelected || lgSelected === "new" || legalLinkPicker.caseId !== lgSelected) return;
  legalLinkPicker.query = String(value||"");
  clearTimeout(legalLinkTimer);
  legalLinkTimer = setTimeout(()=>{ void lgLinkSearch(); }, 250);
}
async function lgLinkSearch(){
  const caseId = lgSelected;
  if (!caseId || caseId === "new" || legalLinkPicker.caseId !== caseId) return;
  const q = legalLinkPicker.query.trim();
  const seq = ++legalLinkPicker.seq;
  legalLinkPicker.err = "";
  if (q.length < 2){ legalLinkPicker.results=[]; legalLinkPicker.linked=[]; legalLinkPicker.busy=false; paintLinkResults(); return; }
  legalLinkPicker.busy = true; paintLinkResults();
  // RLS on cases (can_see_case) silently limits results to cases the viewer
  // may see, which is exactly the set they are allowed to link.
  const { data, error } = await sb.from("cases").select("id,ref,intake_type,category,state")
    .ilike("ref",`%${q.replace(/[%_\\]/g,"")}%`).order("ref").limit(8);
  if (seq !== legalLinkPicker.seq || lgSelected !== caseId) return;
  legalLinkPicker.busy = false;
  // Split AFTER the await so the "Already linked" set reflects any link or
  // unlink that landed while the query was in flight.
  const already = new Set((legalDetail.links||[]).map(l=>l.linked_case_id));
  if (error){ legalLinkPicker.err = errText(error); paintLinkResults(); return; }
  legalLinkPicker.results = (data||[]).filter(c=>!already.has(c.id));
  legalLinkPicker.linked  = (data||[]).filter(c=>already.has(c.id));
  paintLinkResults();
}
async function lgLinkCase(caseId){
  const legalId = lgSelected;
  if (!legalId || legalId === "new") return;
  const ctx = legalActionContext(legalId), picker = legalLinkPicker;
  const { error } = await sb.rpc("legal_link_case",{ p_legal_case_id: legalId, p_case_id: caseId });
  // An in-flight summary action must never repaint a subsequently opened
  // editor. Returning to the summary refetches the committed link normally.
  if (!ctx.visible() || lgEditing || legalLinkPicker !== picker) return;
  if (error){ legalLinkPicker.err = errText(error); paintLinkResults(); return; }
  legalLinkPicker = { caseId: legalId, query:"", results:[], linked:[], busy:false, err:"", seq: legalLinkPicker.seq };
  render();
}
async function lgUnlinkCase(linkId, ref){
  const legalId = lgSelected;
  if (!legalId || legalId === "new") return;
  if (!confirm(`Remove linked case ${ref}?\n\nRemoving it removes that case's evidence and documents from this legal case's view. The case itself and its files are NOT deleted.`)) return;
  const ctx = legalActionContext(legalId), picker = legalLinkPicker;
  const { error } = await sb.rpc("legal_unlink_case",{ p_link_id: linkId });
  if (!ctx.visible() || lgEditing || legalLinkPicker !== picker) return;
  if (error){ alert(errText(error)); return; }
  // Drop the link from local state synchronously so anything that reads
  // legalDetail.links before the refetch lands (e.g. the search refresh
  // below) already sees it gone; render() then refetches the real rows.
  legalDetail.links = (legalDetail.links||[]).filter(l=>l.id!==linkId);
  render();
  // The unlinked case may now match the open search again — refresh so a
  // stale "Already linked" chip doesn't outlive the link it described.
  if (legalLinkPicker.caseId === legalId && legalLinkPicker.query.trim().length >= 2) void lgLinkSearch();
}
async function lgLinkedEvidenceDownload(caseId, fname){
  const legalId = lgSelected;
  const listed = (legalDetail.links||[]).some(l=>l.linked_case_id===caseId)
    && (legalDetail.linkedFiles[caseId]?.evidence||[]).some(f=>f.name===fname);
  if (!legalId || legalId === "new" || !listed || /[\\/]/.test(fname)){ alert("This file is not linked to the open legal case."); return; }
  const ctx = legalActionContext(legalId);
  const { data, error } = await sb.storage.from("evidence").download(`${caseId}/${fname}`);
  if (!ctx.visible()) return;
  if (error || !data){ alert("Could not download this file: " + (error?.message||"unknown error")); return; }
  downloadBlob(data, legalDocumentName(fname).replace(/^\d+_/,''));
}
async function lgLinkedEvidencePreview(caseId, fname, displayName){
  const legalId = lgSelected;
  const listed = (legalDetail.links||[]).some(l=>l.linked_case_id===caseId)
    && (legalDetail.linkedFiles[caseId]?.evidence||[]).some(f=>f.name===fname);
  if (!legalId || legalId === "new" || !listed || /[\\/]/.test(fname)){ alert("This file is not linked to the open legal case."); return; }
  const meta = (legalDetail.linkedFiles[caseId]?.evidence||[]).find(f=>f.name===fname);
  await openAttachmentPreview({ name: displayName||legalDocumentName(fname), type: meta?.metadata?.mimetype||"",
    isCurrent: ()=>lgSelected===legalId && (legalDetail.links||[]).some(l=>l.linked_case_id===caseId)
      && (legalDetail.linkedFiles[caseId]?.evidence||[]).some(f=>f.name===fname),
    authorize: async()=>{ const {data,error}=await sb.storage.from("evidence").createSignedUrl(`${caseId}/${fname}`,120);
      return { url:data?.signedUrl, error, note:"Private preview access expires after two minutes." }; },
    download: ()=>lgLinkedEvidenceDownload(caseId,fname) });
}
function linkedCaseFile(caseId,path,name){
  if (!(legalDetail.links||[]).some(l=>l.linked_case_id===caseId)) return null;
  return (legalDetail.linkedFiles[caseId]?.caseFiles||[]).find(file=>file.storage_path===path&&file.file_name===name) || null;
}
async function lgLinkedCaseFileDownload(caseId,path,name){
  const legalId=lgSelected,file=linkedCaseFile(caseId,path,name);
  if(!legalId||legalId==="new"||!file||!caseFilePathAllowed(file,caseId)){alert("This file is not linked to the open legal case.");return;}
  const ctx=legalActionContext(legalId),source=legalDetail;
  const {data,error}=await sb.storage.from("evidence").download(path);
  if(!ctx.visible()||legalDetail!==source||!linkedCaseFile(caseId,path,name))return;
  if(error||!data){alert("Could not download this file: "+(error?.message||"unknown error"));return;}
  downloadBlob(data,name||path.split("/").pop());
}
async function lgLinkedCaseFilePreview(caseId,path,name,type,restoreId){
  const legalId=lgSelected,file=linkedCaseFile(caseId,path,name);
  if(!legalId||legalId==="new"||!file||!caseFilePathAllowed(file,caseId)){alert("This file is not linked to the open legal case.");return;}
  await openAttachmentPreview({name,type,restoreId,
    isCurrent:()=>lgSelected===legalId&&!!linkedCaseFile(caseId,path,name),
    authorize:async()=>{const {data,error}=await sb.storage.from("evidence").createSignedUrl(path,120);return {url:data?.signedUrl,error,note:"Private preview access expires after two minutes."};},
    download:()=>lgLinkedCaseFileDownload(caseId,path,name)});
}
function linkedMessageFile(caseId,attachmentId){
  if (!(legalDetail.links||[]).some(l=>l.linked_case_id===caseId)) return null;
  return (legalDetail.linkedFiles[caseId]?.messageFiles||[]).find(file=>file.id===attachmentId) || null;
}
async function lgLinkedMessageDownload(caseId,attachmentId,name){
  const legalId=lgSelected,file=linkedMessageFile(caseId,attachmentId);
  if(!legalId||legalId==="new"||!file){alert("This file is not linked to the open legal case.");return;}
  const ctx=legalActionContext(legalId),source=legalDetail;
  const authorized=await authorizeMessageAttachment(caseId,"",attachmentId,"");
  if(!ctx.visible()||legalDetail!==source||!linkedMessageFile(caseId,attachmentId))return;
  if(!authorized.url){alert("Could not authorize this download: "+(authorized.error?.message||"unknown error"));return;}
  const a=document.createElement("a");a.href=authorized.url;a.download=name||file.name||"attachment";a.target="_blank";a.rel="noopener noreferrer";a.referrerPolicy="no-referrer";document.body.appendChild(a);a.click();a.remove();
}
async function lgLinkedMessagePreview(caseId,attachmentId,name,type,restoreId){
  const legalId=lgSelected,file=linkedMessageFile(caseId,attachmentId);
  if(!legalId||legalId==="new"||!file){alert("This file is not linked to the open legal case.");return;}
  await openAttachmentPreview({name,type,restoreId,
    isCurrent:()=>lgSelected===legalId&&!!linkedMessageFile(caseId,attachmentId),
    authorize:()=>authorizeMessageAttachment(caseId,"",attachmentId,""),
    download:()=>lgLinkedMessageDownload(caseId,attachmentId,name)});
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
    <div class="legal-editor-head" style="display:flex;align-items:center;gap:10px">
      <b style="font-size:16px">${r ? `${esc(r.ref)} — edit case` : "New legal / claims case"}</b>
      ${r && lgDue(r) ? '<span class="pill due-over">Due follow-up</span>' : ""}
      <button class="btn sm ghost" style="margin-left:auto" onclick="lgCancelEdit()">Cancel</button>
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
      <div><label>Complainant</label>${employeeLookupHtml(registerEmployeeLookup("lg-complainant", {
        ariaLabel:"Search employees for the complainant",
        placeholder:"Fill from the employee directory (optional)…",
        getSelected: () => null,
        onPick: d => { const inp=$("lg-complainant"); if(inp) inp.value = `${d.name} (${d.employee_id})`; elRepaint("lg-complainant"); },
      }))}<input id="lg-complainant" type="text" value="${v('complainant')}"></div>
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
    <div class="mini-l" style="margin-top:12px">Outcome &amp; financials</div>
    <div class="grid2">
      <div><label>Settlement amount <span class="muted" style="font-weight:400;text-transform:none;letter-spacing:0">(agreed, USD)</span></label><input id="lg-settlement_amount" type="text" inputmode="decimal" autocomplete="off" placeholder="0.00" value="${v('settlement_amount')}"></div>
      <div><label>Penalty amount <span class="muted" style="font-weight:400;text-transform:none;letter-spacing:0">(court-ordered, USD)</span></label><input id="lg-penalty_amount" type="text" inputmode="decimal" autocomplete="off" placeholder="0.00" value="${v('penalty_amount')}"></div>
    </div>
    <div><label>Violation description</label><textarea id="lg-violation_description" rows="2">${v('violation_description')}</textarea></div>
    <div class="mini-l" style="margin-top:12px">Follow-up</div>
    <div><label>Pending action</label><textarea id="lg-pending_action" rows="2">${v('pending_action')}</textarea></div>
    <div class="grid2">
      <div><label>Due date</label><input id="lg-due_date" type="date" value="${d('due_date')}"></div>
      <div><label>Due date note <span class="muted" style="font-weight:400;text-transform:none;letter-spacing:0">(original text when the date was messy)</span></label><input id="lg-due_date_note" type="text" value="${v('due_date_note')}"></div>
    </div>
    <div><label>Existing related documents folder link</label><input id="lg-docs_link" type="text" value="${v('docs_link')}" placeholder="https://…"></div>
    <div id="lg-err"></div>
    <div class="mobile-form-actions"><button class="btn ghost" onclick="lgCancelEdit()">Cancel</button><button class="btn" onclick="lgSave()">${r?"Save changes":"Create case"}</button></div>
  </div>`;
}
function blankLegalComposer(caseId=null){ return {caseId,note:"",files:[],status:"",error:"",noteError:"",retry:false}; }
function blankLegalPreview(){ return {open:false,caseId:null,storedName:"",name:"",url:"",kind:""}; }
function lgOpen(id){ closeAttachmentPreview(false); lgSelected = id; lgEditing = id === "new"; legalComposer=blankLegalComposer(id==="new"?null:id); legalLinkPicker={caseId:id==="new"?null:id,query:"",results:[],linked:[],busy:false,err:"",seq:legalLinkPicker.seq+1}; legalBusy={note:false,upload:false}; legalPreview=blankLegalPreview(); legalPreviewGeneration+=1; render(); syncRoute(); window.scrollTo({top:0,behavior:"smooth"}); }
function lgClose(){ closeAttachmentPreview(false); lgSelected = null; lgEditing = false; legalComposer=blankLegalComposer(); legalLinkPicker={caseId:null,query:"",results:[],linked:[],busy:false,err:"",seq:legalLinkPicker.seq+1}; legalBusy={note:false,upload:false}; legalPreview=blankLegalPreview(); legalPreviewGeneration+=1; render(); syncRoute(); }
function lgEdit(){ if(lgSelected && lgSelected!=="new"){ lgEditing=true; render(); } }
function lgCancelEdit(){ if(lgSelected==="new") lgClose(); else { lgEditing=false; render(); } }
async function lgSave(){
  const F = ["case_state","risk_level","status","complainant","claim_type",
    "opposing_counsel","company_counsel","eb_point","synopsis",
    "epli_tendered","epli_notes","pending_action",
    "due_date","due_date_note","docs_link",
    "settlement_amount","penalty_amount","violation_description"];
  const p = {};
  for (const f of F) p[f] = ($("lg-"+f)?.value ?? "").trim();
  const err = m => { const el=$("lg-err"); el.innerHTML = `<div class="banner err">${esc(m)}</div>`; el.scrollIntoView({behavior:"smooth",block:"center"}); };
  // The workbook has rows identified only by their synopsis (e.g. "Privacy"),
  // so either field is enough — but a fully unlabeled row helps no one.
  if (!p.complainant && !p.synopsis){ err("Enter a complainant or a synopsis."); return; }
  // The amount fields are type="text" on purpose: type="number" silently
  // DISCARDS a pasted "12,500.50" from a demand letter (blank field, no error,
  // indistinguishable from "no amount" on save). Accept common currency
  // formatting — strip $ , and whitespace — then fail anything still
  // non-numeric with a readable #lg-err banner instead of a numeric-cast
  // error from the database. The stripped plain string is what gets saved.
  for (const [k,label] of [["settlement_amount","settlement amount"],["penalty_amount","penalty amount"]]){
    p[k] = p[k].replace(/[$,\s]/g,"");
    if (p[k] && (!Number.isFinite(Number(p[k])) || Number(p[k]) < 0)){ err(`Enter a valid non-negative ${label} — e.g. 12500.50 ($ signs and commas are OK).`); return; }
  }
  const { error } = await sb.rpc("legal_save", { p_id: lgSelected === "new" ? null : lgSelected, p });
  if (error){ err(errText(error)); return; }
  if (lgSelected === "new") lgSelected = null;
  lgEditing = false; render(); syncRoute();
}
function legalStoragePath(caseId, storedName){
  const id = String(caseId||"");
  const name = String(storedName||"");
  if (!/^[A-Za-z0-9_-]{1,80}$/.test(id) || !name || /[\\/]/.test(name) || name === "." || name === "..") return null;
  return `legal/${id}/${name}`;
}
function legalUploadName(fileName){
  const cleaned = String(fileName||"document").replace(/[\\/\x00-\x1f\x7f]/g,"_").slice(-180) || "document";
  const unique = globalThis.crypto?.randomUUID?.() || `${Date.now()}-${Math.random().toString(36).slice(2)}`;
  return `${unique}_${cleaned}`;
}
function legalActionContext(caseId){
  const epoch=sessionEpoch, userId=session?.user?.id;
  const sameIdentity=()=>epoch===sessionEpoch && session?.user?.id===userId
    && lgSelected===caseId && legalComposer.caseId===caseId;
  return { sameIdentity, visible:()=>sameIdentity() && view==="dashboard" && dashView==="legal" };
}
function lgSetNoteDraft(value){
  if (legalComposer.caseId===lgSelected) legalComposer.note=String(value||"");
}
function lgSetFiles(input){
  if (legalComposer.caseId!==lgSelected) return;
  legalComposer.files=Array.from(input?.files||[]); legalComposer.status=""; legalComposer.error=""; legalComposer.retry=false;
  const staged=$("lg-staged-files");
  const label=legalComposer.files.length?`Selected for upload: ${legalComposer.files.map(f=>f.name).join(", ")}`:"";
  if(staged) staged.textContent=label;
}
function setLegalActionBusy(kind, active){
  const button=$(kind==="note"?"lg-note-action":"lg-upload-action");
  if(button){ button.disabled=active; button.setAttribute("aria-busy",String(active)); button.textContent=active?(kind==="note"?"Adding…":"Uploading…"):(kind==="note"?"Add note":legalComposer.retry?"Retry failed files":"Upload"); }
  const status=$(kind==="note"?"lg-note-status":"lg-doc-status");
  if(active && status) status.innerHTML=`<span class="note-sm">${kind==="note"?"Adding note…":"Uploading documents…"}</span>`;
}
async function lgAddNote(caseId){
  if (legalBusy.note || legalComposer.caseId!==caseId) return;
  const body = legalComposer.note.trim();
  if (!body) return;
  const ctx=legalActionContext(caseId);
  legalBusy.note=true; legalComposer.noteError=""; setLegalActionBusy("note",true);
  const { error } = await sb.rpc("legal_add_note",{p_legal_case_id:caseId,p_body:body});
  if (!ctx.sameIdentity()) return;
  legalBusy.note=false; setLegalActionBusy("note",false);
  if (error){ legalComposer.noteError=errText(error); if(ctx.visible()) render(); return; }
  legalComposer.note=""; if(ctx.visible()) render();
}
function finishLegalUpload(ctx, failures, uploaded, paused=false){
  legalBusy.upload=false; legalComposer.retry=legalComposer.files.length>0; setLegalActionBusy("upload",false);
  legalComposer.status=uploaded?`${uploaded} document${uploaded===1?"":"s"} uploaded successfully.`:"";
  const messages=[];
  if(failures.length) messages.push(`${failures.length} failed: ${failures.join("; ")}.`);
  if(paused && legalComposer.files.length) messages.push(`Upload paused after leaving Legal & Claims; ${legalComposer.files.length} file${legalComposer.files.length===1?" remains":"s remain"} in the retry queue.`);
  else if(failures.length) messages.push(`Select “Retry failed files” to retry only ${failures.length===1?"this file":"these files"}.`);
  legalComposer.error=messages.join(" ");
  if(ctx.visible()) render();
}
async function lgUploadDocuments(caseId){
  if (legalBusy.upload || legalComposer.caseId!==caseId) return;
  const files = [...legalComposer.files];
  if (!files.length) return;
  const oversized=files.find(file=>file.size>25*1024*1024);
  if(oversized){ legalComposer.error=`${oversized.name} is larger than the 25 MB limit.`; legalComposer.status=""; legalComposer.retry=false; render(); return; }
  const ctx=legalActionContext(caseId);
  legalBusy.upload=true; legalComposer.error=""; legalComposer.status=""; setLegalActionBusy("upload",true);
  const failures=[];
  let uploaded=0;
  for (const file of files){
    if (!ctx.sameIdentity()) return;
    if (!ctx.visible()){ finishLegalUpload(ctx,failures,uploaded,true); return; }
    const storedName = legalUploadName(file.name);
    const path = legalStoragePath(caseId,storedName);
    if (!path){ failures.push(`${file.name}: document name could not be prepared safely`); continue; }
    const { error } = await sb.storage.from("evidence").upload(path,file,{upsert:false,contentType:file.type||undefined});
    if (!ctx.sameIdentity()) return;
    if (error){ failures.push(`${file.name}: ${error.message||"unknown error"}`); continue; }
    uploaded += 1;
    legalComposer.files=legalComposer.files.filter(candidate=>candidate!==file);
    if (!ctx.visible()){ finishLegalUpload(ctx,failures,uploaded,true); return; }
  }
  if (!ctx.sameIdentity()) return;
  finishLegalUpload(ctx,failures,uploaded,false);
}
async function lgDownloadDocument(caseId, storedName, displayName){
  const path = legalStoragePath(caseId,storedName);
  if (!path){ alert("This document path is invalid."); return; }
  const ctx=legalActionContext(caseId);
  const { data, error } = await sb.storage.from("evidence").download(path);
  if (!ctx.visible()) return;
  if (error || !data){ alert("Could not download this document: " + (error?.message||"unknown error")); return; }
  downloadBlob(data,displayName||legalDocumentName(storedName));
}
async function lgPreviewDocument(caseId, storedName, displayName){
  const path = legalStoragePath(caseId,storedName);
  const kind = legalDocumentKind(displayName||storedName);
  if (!path || kind === "download"){ alert("Preview is not available for this file type. Download the document instead."); return; }
  const ctx=legalActionContext(caseId);
  const generation=++legalPreviewGeneration;
  const { data, error } = await sb.storage.from("evidence").createSignedUrl(path,120);
  if (!ctx.visible() || generation!==legalPreviewGeneration) return;
  if (error || !data?.signedUrl){ alert("Could not create a private preview link: " + (error?.message||"unknown error")); return; }
  if (kind === "frame"){
    try { await verifyFrameContentType(data.signedUrl, String(displayName||storedName).split(".").pop().toLowerCase()); }
    catch { if(ctx.visible() && generation===legalPreviewGeneration) alert("This file could not be verified for safe preview. Download the original instead."); return; }
    if (!ctx.visible() || generation!==legalPreviewGeneration) return;
  }
  legalPreview = {open:true,caseId,storedName,name:displayName||legalDocumentName(storedName),url:data.signedUrl,kind};
  render();
}
function setLegalPreviewBackgroundInert(active){
  if (!active){
    document.querySelectorAll('[data-legal-preview-inert="1"]').forEach(el=>{ el.inert=false; delete el.dataset.legalPreviewInert; });
    return;
  }
  document.querySelectorAll("header.top, nav, #app > *:not(.legal-preview-overlay)").forEach(el=>{
    el.inert=true; el.dataset.legalPreviewInert="1";
  });
}
function handleLegalPreviewKeydown(event){
  if (!legalPreview.open) return;
  if(event.key==="Escape"){ event.preventDefault(); event.stopPropagation(); lgClosePreview(); return; }
  if(event.key!=="Tab") return;
  const controls=[$("lg-preview-download"),$("lg-preview-close")].filter(Boolean);
  if(!controls.length) return;
  const first=controls[0], last=controls.at(-1), active=document.activeElement;
  if(event.shiftKey && (active===first || !controls.includes(active))){ event.preventDefault(); last.focus(); }
  else if(!event.shiftKey && (active===last || !controls.includes(active))){ event.preventDefault(); first.focus(); }
}
function lgClosePreview(){ legalPreviewRestoreName=legalPreview.storedName||""; setLegalPreviewBackgroundInert(false); legalPreview=blankLegalPreview(); legalPreviewGeneration+=1; render(); }
function lgPreviewModal(){
  return `<div class="modal-overlay legal-preview-overlay" role="presentation" onclick="if(event.target===this)lgClosePreview()">
    <div class="modal legal-preview-modal" role="dialog" aria-modal="true" aria-label="Preview ${esc(legalPreview.name)}">
      <div class="legal-section-head"><div><div class="mini-l">Document preview</div><b>${esc(legalPreview.name)}</b></div><span style="display:flex;gap:6px"><button id="lg-preview-download" class="btn sm ghost" data-p="${esc(legalPreview.storedName)}" data-n="${esc(legalPreview.name)}" onclick="lgDownloadDocument('${esc(legalPreview.caseId)}',this.dataset.p,this.dataset.n)">Download</button><button id="lg-preview-close" class="btn sm ghost" autofocus onclick="lgClosePreview()">Close</button></span></div>
      <div class="legal-preview-canvas">${legalPreview.kind==="image"
        ? `<img src="${esc(legalPreview.url)}" alt="Preview of ${esc(legalPreview.name)}" referrerpolicy="no-referrer">`
        : `<iframe src="${esc(legalPreview.url)}" title="Preview of ${esc(legalPreview.name)}" referrerpolicy="no-referrer" tabindex="-1"></iframe>`}</div>
      <p class="note-sm">Private preview links expire after two minutes.</p>
    </div></div>`;
}

// ---- private file preview shared by case, email, and message attachments ----
// HTML, SVG, and Office files intentionally stay download-only. Text is fetched
// and escaped into <pre>; PDFs load in a cross-origin frame WITHOUT the sandbox
// attribute — Chromium refuses to run its PDF viewer in a sandboxed frame under
// any token combination, so isolation relies on the storage host being a
// different origin than the app. Common raster formats render as images.
// Every caller must authorize the exact file for its surface.
// Check the served type, not uploader metadata or the filename alone. Objects
// are immutable to uploaders; redirects must not change the verified origin.
async function verifyFrameContentType(url,extension="pdf"){
  const target=new URL(url), origin=new URL(cfg.SUPABASE_URL).origin;
  const allowed={pdf:["application/pdf"],txt:["text/plain"],csv:["text/csv","text/plain"]}[extension]||[];
  if(target.protocol!=="https:" || target.origin!==origin || target.username || target.password || !allowed.length) throw new Error("Unsafe preview URL");
  const response=await fetch(target.href,{method:"HEAD",credentials:"omit",referrerPolicy:"no-referrer",redirect:"error",cache:"no-store"});
  const type=(response.headers.get("content-type")||"").split(";")[0].trim().toLowerCase();
  if(!response.ok || !allowed.includes(type)) throw new Error("Unsafe preview content type");
}
function attachmentKind(name,type=""){
  const ext=String(name||"").split(".").pop().toLowerCase();
  if(["png","jpg","jpeg","gif","webp"].includes(ext) && /^image\/(png|jpeg|gif|webp)$/i.test(type||`image/${ext==='jpg'?'jpeg':ext}`)) return "image";
  if(ext==="pdf" && (!type || type==="application/pdf")) return "pdf";
  if(["txt","csv"].includes(ext) && (!type || /^text\/(plain|csv)$/i.test(type))) return "text";
  if(["mp3","wav","ogg","m4a"].includes(ext) && (!type || /^audio\/(mpeg|wav|ogg|mp4|x-m4a)$/i.test(type))) return "audio";
  if(["mp4","webm"].includes(ext) && (!type || /^(video\/(mp4|webm)|audio\/mp4)$/i.test(type))) return "video";
  return "download";
}
function attachmentPreviewHtml(){
  const p=attachmentPreview;
  const body=p.kind==="image"?`<img src="${esc(p.url)}" alt="Preview of ${esc(p.name)}" referrerpolicy="no-referrer">`
    :p.kind==="pdf"?`<iframe src="${esc(p.url)}" title="Preview of ${esc(p.name)}" referrerpolicy="no-referrer" tabindex="-1"></iframe>`
    :p.kind==="audio"?`<audio src="${esc(p.url)}" controls preload="metadata" aria-label="Preview of ${esc(p.name)}"></audio>`
    :p.kind==="video"?`<video src="${esc(p.url)}" controls preload="metadata" playsinline aria-label="Preview of ${esc(p.name)}"></video>`
    :`<pre class="attachment-text-preview">${esc(p.text)}</pre>`;
  return `<div id="attachment-preview" class="modal-overlay legal-preview-overlay" role="presentation" onclick="if(event.target===this)closeAttachmentPreview()">
    <div class="modal legal-preview-modal" role="dialog" aria-modal="true" aria-label="Preview ${esc(p.name)}">
      <div class="legal-section-head"><div><div class="mini-l">Private document preview</div><b>${esc(p.name)}</b></div><span class="preview-actions"><button id="attachment-preview-download" class="btn sm ghost" onclick="downloadOpenAttachment()">Download</button><button id="attachment-preview-close" class="btn sm ghost" onclick="closeAttachmentPreview()">Close</button></span></div>
      <div class="legal-preview-canvas">${body}</div><p class="note-sm">${esc(p.note||"Private access expires shortly. Download the original if preview is unavailable.")}</p>
    </div></div>`;
}
function setAttachmentPreviewBackgroundInert(active){
  document.querySelectorAll('[data-attachment-preview-inert="1"]').forEach(el=>{el.inert=false;delete el.dataset.attachmentPreviewInert;});
  if(active) document.querySelectorAll("header.top, nav, main").forEach(el=>{el.inert=true;el.dataset.attachmentPreviewInert="1";});
}
async function openAttachmentPreview({name,type="",kindOverride="",authorize,download,restoreId="",isCurrent=()=>true}){
  const kind=["image","pdf"].includes(kindOverride)?kindOverride:attachmentKind(name,type);
  if(kind==="download"){ alert("Preview is not available for this file type. Download the original instead."); return; }
  closeAttachmentPreview(false);
  const epoch=sessionEpoch, generation=++attachmentPreviewGeneration;
  let authorized;
  try { authorized=await authorize(); } catch(error){ authorized={error}; }
  if(epoch!==sessionEpoch || generation!==attachmentPreviewGeneration || !isCurrent()) return;
  if(!authorized?.url){ alert("Could not create a private preview link: "+(authorized?.error?.message||authorized?.error||"unknown error")); return; }
  if(kind==="pdf"){
    try { await verifyFrameContentType(authorized.url); }
    catch { if(epoch===sessionEpoch && generation===attachmentPreviewGeneration && isCurrent()) alert("This file could not be verified for safe preview. Download the original instead."); return; }
    if(epoch!==sessionEpoch || generation!==attachmentPreviewGeneration || !isCurrent()) return;
  }
  let text="";
  if(kind==="text"){
    try {
      const response=await fetch(authorized.url,{credentials:"omit",referrerPolicy:"no-referrer"});
      if(!response.ok) throw new Error("preview download failed");
      const blob=await response.blob();
      if(blob.size>2*1024*1024) throw new Error("Text preview is limited to 2 MB");
      text=await blob.text();
    } catch(error){ if(epoch===sessionEpoch && generation===attachmentPreviewGeneration && isCurrent()) alert(`${error.message}. Download the original instead.`); return; }
  }
  if(epoch!==sessionEpoch || generation!==attachmentPreviewGeneration || !isCurrent()) return;
  attachmentPreview={open:true,name,url:authorized.url,text,kind,note:authorized.note||"Private access expires shortly.",download,restoreId};
  document.body.insertAdjacentHTML("beforeend",attachmentPreviewHtml());
  setAttachmentPreviewBackgroundInert(true);
  requestAnimationFrame(()=>$('attachment-preview-close')?.focus());
}
function handleAttachmentPreviewKeydown(event){
  if(!attachmentPreview.open) return;
  if(event.key==="Escape"){event.preventDefault();event.stopPropagation();closeAttachmentPreview();return;}
  if(event.key!=="Tab") return;
  const controls=[$("attachment-preview-download"),$("attachment-preview-close")].filter(Boolean);
  const first=controls[0],last=controls.at(-1),active=document.activeElement;
  if(event.shiftKey&&(active===first||!controls.includes(active))){event.preventDefault();last?.focus();}
  else if(!event.shiftKey&&(active===last||!controls.includes(active))){event.preventDefault();first?.focus();}
}
function closeAttachmentPreview(restore=true){
  const restoreId=attachmentPreview.restoreId;
  attachmentPreviewGeneration+=1; attachmentPreview={open:false,name:"",url:"",text:"",kind:"",note:"",download:null,restoreId:""};
  $("attachment-preview")?.remove(); setAttachmentPreviewBackgroundInert(false);
  if(attachmentPreviewObjectUrl){URL.revokeObjectURL(attachmentPreviewObjectUrl);attachmentPreviewObjectUrl="";}
  if(restore&&restoreId) requestAnimationFrame(()=>$(`${restoreId}`)?.focus());
}
async function downloadOpenAttachment(){
  const action=attachmentPreview.download;
  if(typeof action==="function") await action();
}

// ---- reporter-visible two-way messaging attachments -----------------------
const MESSAGE_FILE_RULES={maxFiles:5,maxFileBytes:10*1024*1024,maxTotalBytes:25*1024*1024};
const MESSAGE_MIME_BY_EXTENSION={pdf:["application/pdf"],png:["image/png"],jpg:["image/jpeg"],jpeg:["image/jpeg"],gif:["image/gif"],webp:["image/webp"],txt:["text/plain"],csv:["text/csv","text/plain"],doc:["application/msword"],docx:["application/vnd.openxmlformats-officedocument.wordprocessingml.document"],xls:["application/vnd.ms-excel"],xlsx:["application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"]};
function messageFileType(file){const name=String(file?.name||""),ext=name.includes(".")?name.split(".").pop().toLowerCase():"",raw=String(file?.type||"").toLowerCase();if(ext==="csv"&&raw==="application/vnd.ms-excel")return "text/csv";return raw||MESSAGE_MIME_BY_EXTENSION[ext]?.[0]||"";}
function blankMessageThread(caseId=null,claimCode=null,caseRef=null){return {key:caseId||claimCode||caseRef?`${caseId||caseRef||"claim"}:${claimCode||"signed"}`:"",caseId,claimCode,caseRef,messages:[],body:"",files:[],busy:false,error:"",status:"",requestId:null,prepared:null,uploaded:[],snapshot:null};}
function ensureMessageThread(caseId=null,claimCode=null,caseRef=null){
  const key=caseId||claimCode||caseRef?`${caseId||caseRef||"claim"}:${claimCode||"signed"}`:"";
  if(messageThread.key!==key) messageThread=blankMessageThread(caseId,claimCode,caseRef);
  return messageThread;
}
async function messageAttachmentAction(body){
  const {data,error}=await sb.functions.invoke("message-attachments",{body});
  if(error){
    let detail=null;
    try{if(error.context?.clone)detail=await error.context.clone().json();}catch{}
    const apiError=detail?.error||detail;
    return {data:null,error:{code:apiError?.code||"INTERNAL",message:apiError?.message||error.message||"Message attachments are temporarily unavailable."}};
  }
  if(data?.error)return {data:null,error:data.error};
  return {data,error:null};
}
async function loadMessageThread(caseId=null,claimCode=null,caseRef=null){
  const thread=ensureMessageThread(caseId,claimCode,caseRef),generation=++messageThreadGeneration,epoch=sessionEpoch;
  const {data,error}=await messageAttachmentAction({action:"list",mode:claimCode||caseRef?"reporter":"handler",...(caseId?{caseId}:{}),...(caseRef?{caseRef}:{}),...(claimCode?{claimCode}:{})});
  if(epoch!==sessionEpoch||generation!==messageThreadGeneration||messageThread!==thread)return false;
  if(error){thread.error="Messages could not be refreshed. "+error.message;return false;}
  thread.messages=Array.isArray(data?.messages)?data.messages:[];thread.error="";return true;
}
function messageAttachmentHtml(file,caseId,claimCode,index,caseRef){
  const kind=attachmentKind(file.name,file.type||""),id=String(file.id||"");
  return `<span class="message-file"><span class="message-file-name">${esc(file.name)}</span><span class="muted">${fmtBytes(file.size)}</span><span class="file-actions">${kind!=="download"?`<button id="message-preview-${esc(id||index)}" class="btn sm sec" data-case="${esc(caseId||'')}" data-ref="${esc(caseRef||'')}" data-claim="${esc(claimCode||'')}" data-id="${esc(id)}" data-n="${esc(file.name)}" data-t="${esc(file.type||'')}" onclick="previewMessageAttachment(this.dataset.case,this.dataset.claim,this.dataset.id,this.dataset.n,this.dataset.t,this.id,this.dataset.ref)">Preview</button>`:""}<button class="btn sm ghost" data-case="${esc(caseId||'')}" data-ref="${esc(caseRef||'')}" data-claim="${esc(claimCode||'')}" data-id="${esc(id)}" data-n="${esc(file.name)}" onclick="downloadMessageAttachment(this.dataset.case,this.dataset.claim,this.dataset.id,this.dataset.n,this.dataset.ref)">Download</button></span></span>`;
}
function messageThreadHtml(caseId,claimCode,isHr,caseRef=null){
  const thread=ensureMessageThread(caseId,claimCode,caseRef),messages=thread.messages||[];
  return `<div class="msgwrap" style="margin:12px 0">${messages.length?messages.map((m,mi)=>`<div class="msg ${m.sender==='handler'?'handler':'reporter'}"><div class="who">${m.sender==='handler'?'HR':(isHr?'Reporter':'You')}${m.viaEmail?' · via email':''}</div>${m.body?linkify(m.body):''}${(m.attachments||[]).length?`<div class="message-files">${m.attachments.map((f,fi)=>messageAttachmentHtml(f,caseId,claimCode,`${mi}-${fi}`,caseRef)).join("")}</div>`:""}</div>`).join(""):'<span class="muted">No messages yet.</span>'}</div>
    <div class="message-compose"><textarea id="message-body" rows="2" maxlength="10000" placeholder="${isHr?'Message the reporter…':'Reply to HR…'}" oninput="setMessageBody(this.value)">${esc(thread.body)}</textarea><input id="message-files" type="file" multiple aria-describedby="message-file-list message-status" onchange="setMessageFiles(this)"><button id="message-send" class="btn ${isHr?'':'sec'}" aria-busy="${thread.busy}" ${thread.busy?'disabled':''} onclick="sendMessageWithAttachments()">${thread.busy?'Sending…':'Send'}</button></div>
    <div id="message-file-list" class="note-sm">${thread.files.length?`Selected: ${thread.files.map(f=>esc(f.name)).join(", ")}`:"Attach up to 5 files (10 MB each, 25 MB total). A message may contain files without text."}</div>
    <div id="message-status" aria-live="polite">${thread.status?`<div class="banner ok">${esc(thread.status)}</div>`:""}${thread.error?`<div class="banner err">${esc(thread.error)}</div>`:""}</div>`;
}
function setMessageBody(value){if(!messageThread.snapshot)messageThread.body=String(value||"");}
function validateMessageFiles(files){
  if(files.length>MESSAGE_FILE_RULES.maxFiles)return "Attach no more than 5 files to one message.";
  let total=0;
  for(const file of files){const name=String(file.name||"").trim(),ext=name.includes(".")?name.split(".").pop().toLowerCase():"",type=messageFileType(file);if(!name||name.length>180||/[\\/\x00-\x1f]/.test(name))return "Each attachment needs a safe filename of 180 characters or fewer.";if(!file.size)return `${file.name} is empty and cannot be attached.`;if(file.size>MESSAGE_FILE_RULES.maxFileBytes)return `${file.name} is larger than 10 MB.`;if(!MESSAGE_MIME_BY_EXTENSION[ext]?.includes(type))return `${file.name} is not an allowed file type. Use PDF, image, text, CSV, Word, or Excel files.`;total+=file.size;}
  return total>MESSAGE_FILE_RULES.maxTotalBytes?"The selected files are larger than the 25 MB message limit.":"";
}
function setMessageFiles(input){
  if(messageThread.snapshot)return;
  const files=Array.from(input?.files||[]),error=validateMessageFiles(files);
  if(error){messageThread.error=error;input.value="";}else{messageThread.files=files;messageThread.error="";messageThread.status="";}
  paintMessageComposer();
}
function paintMessageComposer(){
  const t=messageThread,list=$("message-file-list"),status=$("message-status"),button=$("message-send"),body=$("message-body"),file=$("message-files");
  if(list)list.textContent=t.files.length?`Selected: ${t.files.map(f=>f.name).join(", ")}`:"Attach up to 5 files (10 MB each, 25 MB total). A message may contain files without text.";
  if(status)status.innerHTML=`${t.status?`<div class="banner ok">${esc(t.status)}</div>`:""}${t.error?`<div class="banner err">${esc(t.error)}</div>`:""}`;
  if(button){button.disabled=t.busy;button.setAttribute("aria-busy",String(t.busy));button.textContent=t.busy?"Sending…":t.snapshot?"Retry send":"Send";}
  if(body)body.disabled=t.busy||!!t.snapshot;if(file)file.disabled=t.busy||!!t.snapshot;
}
function messageRequestId(){
  if(globalThis.crypto?.randomUUID)return crypto.randomUUID();
  if(!globalThis.crypto?.getRandomValues)return null;
  const bytes=crypto.getRandomValues(new Uint8Array(16));bytes[6]=(bytes[6]&15)|64;bytes[8]=(bytes[8]&63)|128;
  const hex=[...bytes].map(value=>value.toString(16).padStart(2,"0"));return `${hex.slice(0,4).join("")}-${hex.slice(4,6).join("")}-${hex.slice(6,8).join("")}-${hex.slice(8,10).join("")}-${hex.slice(10).join("")}`;
}
async function sendMessageWithAttachments(){
  const thread=messageThread;if(thread.busy||(!thread.caseId&&!thread.claimCode&&!thread.caseRef))return;
  if(!thread.snapshot){thread.body=$("message-body")?.value??thread.body;const body=thread.body.trim(),fileError=validateMessageFiles(thread.files);if(thread.body.length>10000){thread.error="Messages are limited to 10,000 characters.";paintMessageComposer();return;}if(fileError){thread.error=fileError;paintMessageComposer();return;}if(!body&&!thread.files.length){thread.error="Write a message or attach at least one file.";paintMessageComposer();return;}thread.requestId=messageRequestId();if(!thread.requestId){thread.error="Secure message sending is unavailable in this browser.";paintMessageComposer();return;}thread.snapshot={body,files:[...thread.files]};}
  const epoch=sessionEpoch,generation=messageThreadGeneration,key=thread.key,snapshot=thread.snapshot,userId=session?.user?.id;
  const stillCurrent=()=>epoch===sessionEpoch&&generation===messageThreadGeneration&&session?.user?.id===userId&&messageThread===thread&&thread.key===key
    && (thread.claimCode||thread.caseRef?view==="status":view==="dashboard"&&selected===thread.caseId);
  thread.busy=true;thread.error="";thread.status="";paintMessageComposer();
  try{
    const auth={mode:thread.claimCode||thread.caseRef?"reporter":"handler",...(thread.claimCode?{claimCode:thread.claimCode}:thread.caseRef?{caseRef:thread.caseRef}:thread.caseId?{caseId:thread.caseId}:{})};
    if(!thread.prepared){const {data,error}=await messageAttachmentAction({action:"prepare",...auth,requestId:thread.requestId,files:snapshot.files.map((f,i)=>({clientId:String(i),name:f.name,type:messageFileType(f),size:f.size}))});if(!stillCurrent())return;if(error)throw Object.assign(new Error(error.message),{code:error.code});thread.prepared=data;thread.uploaded=(data.files||[]).filter(file=>file.uploaded===true).map(file=>file.attachmentId);}
    if(thread.prepared)for(const target of thread.prepared.files||[]){if(!stillCurrent())return;if(target.uploaded===true||thread.uploaded.includes(target.attachmentId))continue;const file=snapshot.files[Number(target.clientId)],bucket=target.bucket||"message-attachments";const {error}=await sb.storage.from(bucket).uploadToSignedUrl(target.path,target.token,file,{contentType:target.type||messageFileType(file)});if(!stillCurrent())return;if(error){thread.prepared=null;thread.uploaded=[];throw new Error(`${file.name} could not be uploaded. ${error.message||"Try again."}`);}thread.uploaded.push(target.attachmentId);}
    if(!stillCurrent())return;
    const {error}=await messageAttachmentAction({action:"commit",...auth,requestId:thread.requestId,uploadId:thread.prepared?.uploadId||null,body:snapshot.body});if(error)throw Object.assign(new Error(error.message),{code:error.code});
    if(!stillCurrent())return;
    thread.body="";thread.files=[];thread.requestId=null;thread.prepared=null;thread.uploaded=[];thread.snapshot=null;thread.status="Message sent.";await loadMessageThread(thread.caseId,thread.claimCode,thread.caseRef);
    if(epoch!==sessionEpoch||messageThread.key!==key)return;if(isHandler&&selected===thread.caseId)render();else if(view==="status")render();
  }catch(error){if(!stillCurrent())return;if(["UPLOAD_EXPIRED","UPLOAD_INCOMPLETE","INVALID_FILE","INVALID_REQUEST"].includes(error.code)){thread.prepared=null;thread.uploaded=[];thread.requestId=null;thread.snapshot=null;}thread.error=(error.message||"The message could not be sent.")+" Your text and files are still here; retry when ready.";paintMessageComposer();}
  finally{if(epoch===sessionEpoch&&messageThread.key===key){thread.busy=false;paintMessageComposer();}}
}
async function authorizeMessageAttachment(caseId,claimCode,attachmentId,caseRef){const {data,error}=await messageAttachmentAction({action:"download",mode:claimCode||caseRef?"reporter":"handler",...(claimCode?{claimCode}:caseRef?{caseRef}:caseId?{caseId}:{}),attachmentId});return {url:data?.url,error,note:"Private download access expires after one minute."};}
async function previewMessageAttachment(caseId,claimCode,attachmentId,name,type,restoreId,caseRef){const key=messageThread.key;await openAttachmentPreview({name,type,restoreId,isCurrent:()=>messageThread.key===key&&(view==="status"||selected===caseId),authorize:()=>authorizeMessageAttachment(caseId,claimCode,attachmentId,caseRef),download:()=>downloadMessageAttachment(caseId,claimCode,attachmentId,name,caseRef)});}
async function downloadMessageAttachment(caseId,claimCode,attachmentId,name,caseRef){const epoch=sessionEpoch,key=messageThread.key,userId=session?.user?.id;const authorized=await authorizeMessageAttachment(caseId,claimCode,attachmentId,caseRef);if(epoch!==sessionEpoch||session?.user?.id!==userId||messageThread.key!==key||(claimCode||caseRef?view!=="status":view!=="dashboard"||selected!==caseId))return;if(!authorized.url){alert("Could not authorize this download: "+(authorized.error?.message||"unknown error"));return;}const a=document.createElement("a");a.href=authorized.url;a.download=name||"attachment";a.target="_blank";a.rel="noopener noreferrer";document.body.appendChild(a);a.click();a.remove();}

// 8/18 call: cases are NEVER deleted from the UI any more — a bad/duplicate
// case should be categorized (e.g. "faulty") instead. The delete_case RPC still
// exists server-side but the dashboard no longer offers it. The "faulty"
// category itself needs a schema decision (see PR notes).
function clearSelectedCaseState(){
  selected=null; pendingAdvance=null; showReassign=false; showGuide=false;
  caseExport=null; caseAllegs=[]; evidence={list:[],err:""};
  interviewDrafts.clear();
  partyEditor={ open:false, caseId:null, expectedUpdatedAt:null, parties:[], query:"", role:"subject", busy:false, err:"" };
  medicalPanel=blankMedicalPanel();
}
function openCase(id){ closeAttachmentPreview(false); clearSelectedCaseState(); selected=id; render(); syncRoute(); window.scrollTo({top:0,behavior:"smooth"}); }
function closeCase(){ closeAttachmentPreview(false); clearSelectedCaseState(); render(); syncRoute(); }

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
// The manual box holds either a case or a request (manual.kind). Each kind gets
// its own per-tab slot so a half-typed request can never restore as a case (or
// vice versa) — the two forms have different fields and different submit params.
function draftKindOf(m){ return m && m.kind === "request" ? "request" : "case"; }
function manualSlotId(){ return draftKindOf(manual) === "request" ? TAB_ID + ":request" : TAB_ID; }
function manualDirty(){
  return !!(manual && ((manual.description||"").trim() || (manual.email||"").trim() || (manual.requesterId||"") || (manual.parties||[]).length));
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
    s[manualSlotId()] = { at: Date.now(), manual };
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
function loadManualDraft(kind = "case"){
  const s = readDraftStore();
  let best = null, bestKey = null;
  for (const k of Object.keys(s)){
    if (draftKindOf(s[k].manual) !== kind) continue;
    if (!best || (s[k].at||0) > (best.at||0)) { best = s[k]; bestKey = k; }
  }
  if (!best) return null;
  const m = Object.assign(blankIncident(true), best.manual, { manual:true, kind });
  // Normalize restored types — a malformed stored draft must never break rendering.
  if (!Array.isArray(m.parties)) m.parties = [];
  if (!Array.isArray(m.pRoles) || !m.pRoles.length) m.pRoles = ["subject"];
  if (typeof m.pQuery !== "string") m.pQuery = "";
  if (typeof m.description !== "string") m.description = "";
  if (typeof m.email !== "string") m.email = "";
  // Requester (requests only): keep the stored pick — a requester who has
  // since left the directory is caught at submit (and server-side).
  if (typeof m.requesterId !== "string") m.requesterId = "";
  if (typeof m.requesterName !== "string") m.requesterName = "";
  if (typeof m.requesterAutoEmail !== "string") m.requesterAutoEmail = "";
  if (typeof m.requesterAutoLocation !== "string") m.requesterAutoLocation = "";
  // A location/category that no longer exists would DISPLAY as blank/first-option
  // while the stale value silently submits — keep display and state in agreement.
  // ("Other / not store-specific" is a legal non-store value the select always offers.)
  if (m.location && m.location !== "Other / not store-specific" && !(storeList||[]).includes(m.location)) m.location = "";
  // Requests store the request type in `category` — validate against the right list.
  if (kind === "request"){ if (!REQUEST_TYPES.includes(m.category)) m.category = REQUEST_TYPES[0]; }
  else if (!CATEGORIES.includes(m.category)) m.category = CATEGORIES[0];
  return { at: best.at, key: bestKey, manual: m };
}
function hasManualDraft(kind = "case"){ return loadManualDraft(kind) !== null; }
function clearManualDraft(){
  clearTimeout(draftTimer); draftTimer = null; manualDraftAt = null; draftPending = false;
  try {
    const s = readDraftStore();
    delete s[manualSlotId()];
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
function discardManualDraft(){
  const kind = draftKindOf(manual);           // clearManualDraft targets the slot for the CURRENT kind — read it first
  clearManualDraft();
  manual = manualBlank(kind); errorMsg = ""; renderManualBox();
}
// A blank manual-box state for the given kind (request stores its type in `category`).
function manualBlank(kind){
  const m = blankIncident(true);
  if (kind === "request"){ m.kind = "request"; m.category = REQUEST_TYPES[0]; }
  return m;
}
// Pull DOM-only values into state before any repaint (belt & braces — both
// fields are also bound via oninput below).
function syncManualFields(){
  const d = $("m-desc"), e = $("m-email"), l = $("m-location");
  if (d) manual.description = d.value;
  if (e) manual.email = e.value;
  if (l) manual.location = l.value;
}
// skipSync: callers that just WROTE manual.email/location (requester autofill)
// must not have them clobbered by re-reading the stale DOM inputs.
function renderManualBox(skipSync = false){
  const el = $("manualbox");
  if (!el) { render(); return; }
  if (!skipSync) syncManualFields();
  el.innerHTML = showManual ? (draftKindOf(manual) === "request" ? renderManualRequest() : renderManual()) : "";
}
function toggleManual(){
  showManual = !showManual;
  errorMsg = "";   // never carry a stale error banner into a fresh/restored form
  if (showManual) {
    const kind = dashView === "requests" ? "request" : "case";   // the box adds what the open tab lists
    clearTimeout(draftTimer); draftTimer = null;   // a pending save must not overwrite what we're about to restore
    const d = loadManualDraft(kind);
    if (d) {
      manual = d.manual; manualDraftAt = d.at;
      // Claim the restored slot under THIS tab id immediately — an orphaned
      // slot would survive submit and re-offer the already-filed case as a
      // "draft" days later (duplicate-case risk found in QC).
      draftPending = false;
      if (d.key !== manualSlotId()) try {
        const s = readDraftStore();
        delete s[d.key];
        s[manualSlotId()] = { at: d.at, manual };
        sessionStorage.setItem(draftKey(), JSON.stringify(s));
      } catch {
        // Claim failed (storage broken) — the old slot survives; keep pending so
        // a later successful write still lands, and surface the warning.
        draftPending = true; draftSaveFailed = true;
      }
    }
    else { manual = manualBlank(kind); manualDraftAt = null; draftPending = false; }
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
    <label for="m-location">Location</label>
    ${locationPicker("m-location", manual.location, "setManualLocation", true)}
    <label for="m-category">Category</label>
    <select id="m-category" onchange="setM('category',this.value)">${CATEGORIES.map(c=>`<option ${manual.category===c?'selected':''}>${c}</option>`).join("")}</select>
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
function setManualLocation(value){ setM("location", value, true); }
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
  manual.location = $("m-location")?.value ?? manual.location;
  errorMsg="";
  const chosenLocation = canonicalLocation(manual.location);
  if(chosenLocation === null){ errorMsg=locationError(false); renderManualBox(); return; }
  manual.location = chosenLocation; manual.usState = stateMap[chosenLocation] || "";
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
      p_contact_email:manual.email||null, p_contact_phone:null, p_parties:manual.parties, p_manual:true, p_incident_date:manual.incidentDate||null,
      p_us_state:manual.usState||null }));
  } catch(e) { error = e; }
  if(epoch !== sessionEpoch) return;
  busy=false;
  if(error){ errorMsg = errText(error); renderManualBox(); return; }
  clearManualDraft(); showManual=false; manual=blankIncident(true);
  alert(`Case ${data.ref} added.`); render();
}

// ---- manual REQUEST entry (Vicky 9/14: parity with Cases / Workers' Comp) ----
// Same `manual` state object and draft layer as the manual case form (kind:
// "request"), and the SAME m-email / m-location / m-desc element ids so
// syncManualFields() and paintSaveNote() cover both forms. No party builder or
// incident date — mirrors the employee-facing request intake, which submits
// p_parties:[] and p_incident_date:null.
function renderManualRequest(){
  // T136: the requester is looked up in the employee directory (shared
  // component), so a request can be opened on behalf of someone else.
  // Picking a person auto-fills their location and email from the directory.
  registerEmployeeLookup("m-requester", {
    ariaLabel:"Search employees for the request requester",
    placeholder:"Search the directory by name, title, or employee ID…",
    getSelected: () => manual.requesterId ? { id:manual.requesterId, name:manual.requesterName } : null,
    onPick: pickManualRequester,
    onClear: clearManualRequester,
  });
  // The UI promises location auto-fill — say so when the picked person's
  // directory store doesn't map to a known location (derived, not stored:
  // the note clears itself once a location is chosen).
  const rqDir = manual.requesterId ? dirMap[manual.requesterId] : null;
  const rqStoreUnrecognized = !!(rqDir && rqDir.store && canonicalLocation(rqDir.store) === null && !(manual.location||"").trim());
  return `<div class="card" style="border-color:var(--green)">
    <h2 class="section" style="font-size:16px">Add a request manually <span class="chip">received outside the portal</span></h2>
    ${manualDraftAt?`<div class="banner ok" style="margin:6px 0 10px">Restored your unsaved draft (from ${esc(new Date(manualDraftAt).toLocaleString())}). <a onclick="discardManualDraft()" style="cursor:pointer;font-weight:700;text-decoration:underline">Start fresh instead</a></div>`:""}
    <label>Who is this request for? <span class="muted" style="font-weight:400">(the requester — can be someone other than you)</span></label>
    ${employeeLookupHtml("m-requester")}
    ${rqStoreUnrecognized?`<p class="note-sm" style="margin-top:4px"><b>Their location on file (“${esc(rqDir.store)}”) isn't recognized</b> — pick it manually below.</p>`:""}
    <p class="note-sm" style="margin-top:4px">Picking an employee fills their location and email from the directory. Leave blank if they aren't in it.</p>
    <label>Employee's email (if known)</label><input id="m-email" type="text" value="${esc(manual.email)}" oninput="setM('email',this.value,true)">
    <label for="m-category">Request type</label>
    <select id="m-category" onchange="setM('category',this.value)">${REQUEST_TYPES.map(t=>`<option ${manual.category===t?'selected':''}>${t}</option>`).join("")}</select>
    <label for="m-location">Location (optional)</label>
    ${locationPicker("m-location", manual.location, "setManualLocation", true)}
    <label>Request (paste or describe it as received)</label>
    <textarea id="m-desc" oninput="setM('description',this.value,true)">${esc(manual.description)}</textarea>
    ${draftSaveFailed
      ? `<p id="m-savenote" class="note-sm" style="margin-top:4px;color:var(--red);font-weight:600">Couldn't auto-save this draft in the browser (storage full or blocked) — keep this tab open until you submit.</p>`
      : `<p id="m-savenote" class="note-sm" style="margin-top:4px">Draft auto-saves in this browser as you type and survives a refresh. It's cleared when anyone signs out on this computer.</p>`}
    ${errorMsg?`<div class="banner err">${esc(errorMsg)}</div>`:""}
    <div style="margin-top:14px"><button class="btn" onclick="submitManualRequest()" ${busy?'disabled':''}>${busy?'<span class="spin"></span> Adding…':'Add request'}</button></div>
  </div>`;
}
// T136: selecting / clearing the on-behalf requester. Repaints only the
// manual box (never render() — the dashboard repaint eats unsaved fields).
// requesterAutoEmail/-Location remember exactly what the pick auto-filled so
// clearing the chip can undo it WITHOUT clobbering hand-edited fields.
function pickManualRequester(d){
  syncManualFields();
  manual.requesterId = d.employee_id; manual.requesterName = d.name;
  manual.requesterAutoEmail = ""; manual.requesterAutoLocation = "";
  if (!(manual.email||"").trim() && d.email){ manual.email = d.email; manual.requesterAutoEmail = d.email; }
  const store = canonicalLocation(d.store || "");
  if (!(manual.location||"").trim() && store){ manual.location = store; manual.requesterAutoLocation = store; }
  saveManualDraft(); renderManualBox(true);
}
function clearManualRequester(){
  syncManualFields();
  // Undo the pick's auto-fill only while the field still holds that exact value.
  if (manual.requesterAutoEmail && manual.email === manual.requesterAutoEmail) manual.email = "";
  if (manual.requesterAutoLocation && manual.location === manual.requesterAutoLocation) manual.location = "";
  manual.requesterId = ""; manual.requesterName = "";
  manual.requesterAutoEmail = ""; manual.requesterAutoLocation = "";
  saveManualDraft(); renderManualBox(true);
}
async function submitManualRequest(){
  if (busy) return;
  const epoch = sessionEpoch;
  manual.description = $("m-desc")?.value ?? manual.description;
  manual.email = (($("m-email")?.value ?? manual.email)||"").trim();
  manual.location = $("m-location")?.value ?? manual.location;
  errorMsg="";
  // set_case_requester rejects stale directory ids server-side — catch it
  // before the case is created (e.g. a restored draft naming someone termed).
  if(manual.requesterId && !dirMap[manual.requesterId]){
    errorMsg = "The selected requester is no longer in the employee directory — clear them (×) and pick again, or leave the requester blank.";
    renderManualBox(); return;
  }
  const chosenLocation = canonicalLocation(manual.location);
  if(chosenLocation === null){ errorMsg=locationError(false); renderManualBox(); return; }
  manual.location = chosenLocation; manual.usState = stateMap[chosenLocation] || "";
  if(!manual.description.trim()){ errorMsg="Please paste or describe the request."; renderManualBox(); return; }
  // Server only validates the email format on NON-manual submissions; a bad
  // address here would queue confirmation emails that bounce in the outbox.
  if(manual.email && !/^\S+@\S+\.\S+$/.test(manual.email)){ errorMsg = "The employee's email doesn't look valid — fix it or leave it blank."; renderManualBox(); return; }
  busy=true; renderManualBox();
  let data, error;
  try {
    // One atomic call snapshots the requester and notification email together
    // before awaiting. Later edits cannot mix two people's identities.
    ({ data, error } = await sb.rpc("submit_manual_request", {
      p_category:manual.category, p_description:manual.description,
      p_location:manual.location||null, p_contact_email:manual.email||null,
      p_us_state:manual.usState||null, p_requester_id:manual.requesterId||null }));
  } catch(e) { error = e; }
  if(epoch !== sessionEpoch) return;
  busy=false;
  if(error){ errorMsg = errText(error); renderManualBox(); return; }
  // Creation and requester assignment succeeded in the same transaction.
  clearManualDraft();
  showManual=false; manual=manualBlank("request");
  alert(`Request ${data.ref} added.`); render();
}

// ---- case detail ----
function partyEditHtml(){
  if (!partyEditor.open) return "";
  const results = employeeMatches(partyEditor.query);   // shared accent-insensitive lookup (T136)
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

// T136 fix pass + change flow: set/change control for the structured
// requester on any named request — manual entries AND portal submissions
// (widened 2026-09-16 evening). Restyled 2026-09-16 late to match the Case
// Owner "Reassign" pattern (Eitan): the requester line always carries a
// compact button — "Assign" when no requester is recorded, "Reassign" when
// one is — and the lookup box opens only on demand; nothing auto-opens.
// Handler-only by construction (the case detail view is dashboard-scoped);
// set_case_requester re-checks authorization and the named/request gates
// server-side (migration 20260916210000). Reuses the shared lookup
// component; picking (re-)issues set_case_requester. Scoped repaints only —
// never a full render() from inside this control.
let cdRequester = { caseId:null, err:"", busy:false, open:false };
const cdRequesterEligible = c => c.intake_type === "request" && !c.anonymous;
function cdRequesterState(c){
  if (cdRequester.caseId !== c.id) cdRequester = { caseId:c.id, err:"", busy:false, open:false };
  return cdRequester;
}
function cdRequesterHtml(c){
  if (!cdRequesterEligible(c)) return "";
  const st = cdRequesterState(c);
  if (!st.open) return "";
  registerEmployeeLookup("cd-requester", {
    ariaLabel: c.requester_id ? "Search employees to change the requester" : "Search employees to set the requester",
    placeholder: c.requester_id ? "Search the directory for the new requester…" : "Search the directory to set the requester…",
    getSelected: () => null,
    onPick: d => setCaseRequesterFromDetail(c.id, d.employee_id),
  });
  const note = c.requester_id
    ? "Picking an employee replaces the recorded requester. Status emails keep going to the address the request was submitted with — not to the new requester."
    : "No structured requester is recorded — the dashboard's Requester column and search won't reflect this request until one is set. Status emails keep going to the address the request was submitted with.";
  return `<div id="cd-requester-box" class="kv"><span class="k">${c.requester_id?"Change requester":"Set requester"}</span><span style="flex:1;min-width:240px">
    ${st.busy ? '<span class="muted"><span class="spin"></span> Recording requester…</span>' : employeeLookupHtml("cd-requester")}
    <p class="note-sm" style="margin-top:4px">${note}</p>
    ${st.err?`<div class="banner err">${esc(st.err)}</div>`:""}
  </span></div>`;
}
function cdRequesterToggleHtml(c){
  if (!cdRequesterEligible(c)) return "";
  const st = cdRequesterState(c);
  return `<button id="cd-requester-toggle" class="btn sm ghost" style="margin-left:8px" onclick="toggleCdRequester()" ${st.busy?'disabled':''}>${st.open?'Cancel':(c.requester_id?'Reassign':'Assign')}</button>`;
}
function toggleCdRequester(){
  const c = caseExport?.c;
  if (!c || !cdRequesterEligible(c)) return;
  const st = cdRequesterState(c);
  if (st.busy) return;
  st.open = !st.open; st.err = "";
  if (st.open){ const inst = employeeLookups["cd-requester"]; if (inst){ inst.query = ""; inst.activeIndex = -1; } }
  cdRequesterRepaint(c);
}
function cdRequesterRepaint(c){
  const slot = $("cd-requester-slot"); if (slot) slot.innerHTML = cdRequesterHtml(c);
  const toggle = $("cd-requester-toggle"), toggleHtml = cdRequesterToggleHtml(c);
  if (toggle) toggle.outerHTML = toggleHtml;
  else if (toggleHtml){ const line = $("case-requester-line"); if (line) line.insertAdjacentHTML("afterend", toggleHtml); }
}
async function setCaseRequesterFromDetail(caseId, employeeId){
  const c = caseExport?.c;
  if (!c || c.id !== caseId || cdRequester.busy) return;
  const epoch = sessionEpoch;
  cdRequester = { caseId, err:"", busy:true, open:true }; cdRequesterRepaint(c);
  let error = null;
  try { ({ error } = await sb.rpc("set_case_requester", { p_case_id: caseId, p_employee_id: employeeId })); }
  catch(e){ error = e; }
  if (epoch !== sessionEpoch || selected !== caseId || caseExport?.c?.id !== caseId){
    // Navigated away mid-flight: drop the busy state, or reopening this
    // case would show a permanent spinner (state only resets on caseId change).
    if (cdRequester.caseId === caseId) cdRequester = { caseId:null, err:"", busy:false, open:false };
    return;
  }
  if (error){ cdRequester = { caseId, err:errText(error), busy:false, open:true }; cdRequesterRepaint(c); return; }
  c.requester_id = employeeId;   // requesterLine() now resolves via the directory
  // Mirror the server: reporter_display follows the new pick only when a
  // notification email is on file (non-null reporter_display is the client's
  // only readable proxy for that — see migration 20260915103000).
  // dirMap[employeeId] is guaranteed here only because elPick refuses to
  // fire onPick for ids missing from dirMap.
  const d = dirMap[employeeId];
  if (c.reporter_display && d) c.reporter_display = d.name;
  cdRequester = { caseId, err:"", busy:false, open:false };
  const inst = employeeLookups["cd-requester"]; if (inst){ inst.query = ""; inst.activeIndex = -1; }
  const line = $("case-requester-line"); if (line) line.textContent = requesterLine(c) || "—";
  cdRequesterRepaint(c);
}

async function renderCaseDetailInto(el, id){
  const epoch = sessionEpoch;
  const detailResults = await Promise.all([
    sb.from("cases").select(CASE_DETAIL_COLS).eq("id",id).maybeSingle(),
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
    messageAttachmentAction({action:"list",mode:"handler",caseId:id}),
  ]);
  const [{data:c}, {data:parties}, {data:events}, {data:tasks}, {data:messages}, {data:notes},
         {data:allegs}, {data:ivs}, {data:actions}, {data:cfiles}, messageResult] = detailResults;
  const detailLabels = ["case", "team members", "timeline", "tasks", "messages", "HR notes",
    "allegations", "interviews", "corrective actions", "email attachments"];
  const exportLoadErrors = detailResults.slice(0,detailLabels.length).flatMap((result, index)=>result.error ? [detailLabels[index]] : []);
  if (epoch !== sessionEpoch || selected !== id || !el.isConnected) return;  // stale-paint/session guard
  caseAllegs = allegs || [];   // used by the close modal gate
  if(!c){ el.innerHTML=`<button class="back" onclick="closeCase()">← Back</button><div class="card"><div class="banner warn">This case isn't available to you.</div></div>`; return; }
  const thread=ensureMessageThread(id,null);
  if(messageResult.error) thread.error="Messages could not be refreshed. "+messageResult.error.message;
  else {thread.messages=messageResult.data?.messages||[];thread.error="";}
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
                 files: cfiles||[], exportLoadErrors, handlerName };
  // Loose transitions for both lifecycles; Reopened only offered from Closed.
  const nexts = isReq
    ? (c.state==="Closed" ? ["Assigned"] : REQ_STATES.filter(s=>s!==c.state))
    : (c.state==="Closed" ? ["Reopened"] : INCIDENT_STATES.filter(s=>s!==c.state));
  const canClose = c.state !== "Closed";
  const now = Date.now();
  el.innerHTML = `<button class="back" onclick="closeCase()">← Back to dashboard</button>
  <div class="card">
    <div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap"><span class="ref" style="font-size:16px">${esc(c.ref)}</span>${pill(c.state)}${riskPill(caseRisk(c))}${isReq&&c.accommodation_status?accPill(c.accommodation_status):''}${!isReq&&c.substantiated===true?'<span class="chip">Substantiated</span>':!isReq&&c.substantiated===false?'<span class="chip soft">Unsubstantiated</span>':''}${c.closure_category?`<span class="chip">Closure: ${esc(c.closure_category)}${c.closure_ref?' → '+esc(c.closure_ref):''}</span>`:''}
      <span id="case-export-status" class="note-sm" style="margin-left:auto" role="status" aria-live="polite" aria-atomic="true"></span>
      <button id="case-export-btn" class="btn sm ghost" aria-busy="false" aria-describedby="case-export-status" onclick="exportCaseZip()">Export case (.zip)</button></div>
    <h2 class="section" style="margin-top:6px">${esc(c.category)}</h2>
    <div class="row">
      <div class="col">
        <div class="kv"><span class="k">${L(c,'reporter')}</span>${c.anonymous?'<span class="chip">Anonymous — contact info hidden, system emails them updates</span>':`<b id="case-requester-line">${esc(requesterLine(c)||'—')}</b>${cdRequesterToggleHtml(c)}`}</div>
        <div id="cd-requester-slot">${cdRequesterHtml(c)}</div>
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
  <div class="card"><b>Follow-up tasks &amp; SLAs</b><div style="margin-top:10px">
    ${(tasks||[]).length?tasks.map(t=>{const over=t.status==="open"&&t.due_at&&new Date(t.due_at).getTime()<now;
      return `<div class="task">
        <span style="${t.status==='done'?'text-decoration:line-through;color:var(--grey)':''}">${esc(t.title)}</span>
        <span class="due" style="color:${over?'var(--red)':'var(--grey)'}">${t.status==='done'?'Done':(over?'Overdue':'Due '+fmt(t.due_at))}</span>
        <button class="btn sm ghost" onclick="toggleTask('${t.id}',${t.status!=='done'})">${t.status==='done'?'Reopen':'Mark done'}</button></div>`;}).join(""):'<span class="muted">No tasks.</span>'}
  </div></div>
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
  ${isReq?`<section id="medical-panel" class="card medical-panel" aria-label="Confidential medical documents">
    ${medicalPanelShellHtml(id)}
  </section>`:""}
  <div class="row">
    <div class="col card"><b>${L(c,'evidence')}</b>
      ${isReq?"":'<p class="note-sm" style="margin-top:4px">Doctor notes and other medical paperwork on an incident case belong here under evidence. The identity-verified medical vault applies to accommodation requests only.</p>'}
      <div id="ev-list" style="margin-top:10px">${evidenceHtml(id)}</div>
      <div style="margin-top:10px;display:flex;gap:8px;align-items:center"><input id="ev-file" type="file" multiple style="flex:1"><button class="btn sm sec" onclick="uploadCaseEvidence('${c.id}')">Upload</button></div>
    </div>
  </div>
  ${(cfiles||[]).length?`<div class="card"><b>Files</b> <span class="chip">received by email</span>
    <div style="margin-top:10px">${(cfiles||[]).map(f=>`<div class="task">
      <span>${esc(f.file_name)}<span class="muted" style="font-size:11px"> · ${fmtBytes(f.size_bytes)}${f.source==='email'?' · email':''}${f.uploaded_by?' · from '+esc(f.uploaded_by):''}</span></span>
      <span class="due">${f.created_at?fmt(f.created_at):''}</span>
      ${f.storage_path
        ? `<span class="file-actions">${attachmentKind(f.file_name)!=="download"?`<button id="case-file-preview-${esc(f.id)}" class="btn sm sec" data-p="${esc(f.storage_path)}" data-n="${esc(f.file_name)}" data-t="${esc(f.mime_type||'')}" onclick="caseFilePreview(this.dataset.p,this.dataset.n,this.dataset.t,this.id)">Preview</button>`:""}<button class="btn sm ghost" data-p="${esc(f.storage_path)}" data-n="${esc(f.file_name)}" onclick="caseFileDownload(this.dataset.p,this.dataset.n)">Download</button></span>`
        : (f.email_fallback_url && f.email_fallback_url.startsWith('https://')  // scheme guard (QC 8/31): never render a javascript:/data: href
            ? `<a class="btn sm ghost" href="${esc(f.email_fallback_url)}" target="_blank" rel="noopener noreferrer">Open in mailbox</a>`
            : '<span class="muted" style="font-size:11px">stored in mailbox</span>')}
    </div>`).join("")}
    <p class="note-sm" style="margin-top:8px">Files that arrived by email. Ones too large to store open in the peoplesupport@ mailbox instead (original emails are retained there).</p>
    </div></div>`:""}
  ${!isReq?`<div class="card"><div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap"><b>Interviews</b> <span class="chip">internal — HR team only</span><button class="btn sm ghost" style="margin-left:auto" onclick="downloadBlankStatement()">Download blank ER statement</button></div>
    <p class="note-sm" style="margin-top:4px">Working notes stay editable and separate from the statement responses. Every structured response and local interview detail is saved with this interview.</p>
    <div style="margin-top:10px">
    ${(ivs||[]).length?(ivs||[]).map(iv=>interviewEditorHtml(c.id,iv)).join(""):'<p class="muted">No interviews yet.</p>'}
    </div>
    <div class="divider"></div>
    <span class="mini-l">Add an interview</span>
    <div class="iv-grid" style="margin-top:6px">
      <span><span class="mini-l">Person interviewed</span><input id="ni-name" type="text" placeholder="Name"></span>
      <span><span class="mini-l">Role in case</span><select id="ni-role">${[...PARTY_ROLES,"Other"].map(r=>`<option value="${r}">${rlabel(r)}</option>`).join("")}</select></span>
      <span><span class="mini-l">Date</span><input id="ni-date" type="date"></span>
      <span><span class="mini-l">Local time</span><input id="ni-time" type="time"></span>
      <span><span class="mini-l">Time zone</span>${timezoneSelectHtml("ni-zone",INTERVIEW_TIMEZONES.some(([zone])=>zone===browserTimeZone())?browserTimeZone():"")}</span>
      <span><span class="mini-l">Format</span><select id="ni-format"><option value="">Not recorded</option>${INTERVIEW_FORMATS.map(v=>`<option>${v}</option>`).join("")}</select></span>
      <span><span class="mini-l">Duration (minutes)</span><input id="ni-duration" type="number" min="1" max="1440"></span>
      <span><span class="mini-l">Interviewee title</span><input id="ni-title" type="text"></span>
      <span><span class="mini-l">Interviewee location</span><input id="ni-location" type="text"></span>
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
    ${c.manual_entry&&!c.anonymous&&!c.reporter_display?'<div class="banner warn" style="margin:8px 0">This was added manually with no reporter email on file — messages written here are saved to the case record but can\'t reach the employee. Contact them directly.</div>':''}
    ${messageThreadHtml(id,null,true)}
    ${c.manual_entry&&!c.anonymous&&!c.reporter_display?'':`<p class="note-sm">Messages are also emailed to the reporter automatically${c.anonymous?" — without revealing their address to you":""}.</p>`}
  </div>
  ${closeModal.open?renderCloseModal():""}`;
  // T135 (Ops/People 9/15): identity verification (MFA/QR) is scoped to
  // accommodation requests only — the medical vault panel no longer renders,
  // or triggers the authenticator flow, on incident cases.
  if(isReq&&(medicalPanel.caseId!==id||medicalPanel.status==="idle")) void loadMedicalPanel(id);
}

function medicalPanelShellHtml(caseId){
  if(medicalPanel.caseId!==caseId||medicalPanel.status==="idle"||medicalPanel.status==="loading")return `<div class="medical-head"><div><div class="mini-l">Restricted medical vault</div><b>Confidential medical documents</b></div><span class="spin" aria-label="Checking access"></span></div><p class="note-sm">Checking your access to this separate document area…</p>`;
  const code=medicalPanel.error?.code||"";
  if(medicalPanel.status==="error"){
    if(code==="MFA_REQUIRED")return medicalMfaHtml(caseId);
    const copy=code==="NOT_MEDICAL_STAFF"?"Your account is not assigned to the medical-document team."
      :code==="CASE_UNAVAILABLE"?"This medical file area is unavailable. The case may be outside your assignment or access may have changed."
      :code==="AUTH_REQUIRED"?"Sign in again before opening confidential medical documents."
      :"The confidential medical file service is not configured or is temporarily unavailable.";
    return `<div class="medical-head"><div><div class="mini-l">Restricted medical vault</div><b>Confidential medical documents</b></div><span class="chip">separate access</span></div><div class="banner ${code==="NOT_MEDICAL_STAFF"||code==="CASE_UNAVAILABLE"?'warn':'err'}">${esc(copy)}</div>${!['NOT_MEDICAL_STAFF','CASE_UNAVAILABLE','AUTH_REQUIRED'].includes(code)?`<button class="btn sm ghost" onclick="loadMedicalPanel('${caseId}')">Retry confidential area</button>`:""}<p class="note-sm">The rest of this case remains available according to your usual case access.</p>`;
  }
  const permissions=medicalPanel.capabilities?.permissions||{};
  return `<div class="medical-head"><div><div class="mini-l">Restricted medical vault</div><b>Confidential medical documents</b></div><span class="chip">MFA verified</span></div>
    <div class="banner info medical-boundary"><b>Separate from case evidence.</b> Files here are available only through this restricted panel and are excluded from the ordinary case ZIP export.</div>
    ${permissions.upload?`<div class="medical-upload"><label for="medical-files">Add medical documents</label><input id="medical-files" type="file" multiple accept=".pdf,.png,.jpg,.jpeg,.doc,.docx" onchange="setMedicalFiles(this.files)"><div class="row"><div class="col"><span class="mini-l">Document kind</span><select id="medical-kind"><option value="accommodation">Accommodation</option><option value="fmla">FMLA</option><option value="provider_note">Provider note</option><option value="certification">Certification</option><option value="other">Other medical document</option></select></div><div class="col"><span class="mini-l">Display label (optional)</span><input id="medical-label" maxlength="120" type="text" autocomplete="off"></div></div><button class="btn sm" ${medicalPanel.busy?'disabled aria-busy="true"':''} onclick="uploadMedicalFiles('${caseId}')">${medicalPanel.busy?'Uploading…':'Upload to restricted vault'}</button><span id="medical-upload-status" class="note-sm" role="status">${esc(medicalPanel.status==="upload-error"?medicalPanel.error?.message||"Upload failed.":"")}</span></div>`:""}
    <div class="divider"></div><div class="medical-section-head"><b>Documents</b><span class="muted">${medicalPanel.documents.length}</span></div>
    ${medicalPanel.documents.length?medicalPanel.documents.map((d,i)=>medicalDocumentHtml(caseId,d,i,permissions)).join(""):'<p class="muted">No restricted medical documents have been added.</p>'}
    ${permissions.invite?medicalReturnRequestsHtml(caseId):""}
    ${permissions.audit?medicalOperationsHtml(caseId,permissions):""}`;
}
function medicalMfaHtml(caseId){
  const m=medicalPanel.mfa;
  if(!m.mode)return `<div class="medical-head"><div><div class="mini-l">Restricted medical vault</div><b>Identity check required</b></div><span class="chip">MFA</span></div><p>This confidential area requires a current code from an authenticator app.</p><button class="btn sm" ${m.busy?'disabled aria-busy="true"':''} onclick="startMedicalMfa('${caseId}')">${m.busy?'Starting authenticator…':'Continue with authenticator'}</button>${m.error?`<div class="banner err">${esc(m.error)}</div>`:""}<p class="note-sm">This extra step applies only to the restricted medical-document team.</p>`;
  const qrSrc=medicalMfaQrSrc(m.qr),qr=qrSrc?`<img class="medical-qr" src="${esc(qrSrc)}" alt="Authenticator enrollment QR code" referrerpolicy="no-referrer" onerror="handleMedicalQrError(this)">`:"";
  const qrFallback=m.mode==="enroll"&&!qr?'<div class="banner warn medical-qr-status" role="status">The QR code could not be displayed on this device. Use the setup key below instead.</div>':'<div class="banner warn medical-qr-status" role="status" hidden>The QR code could not be displayed on this device. Use the setup key below instead.</div>';
  return `<div class="medical-head"><div><div class="mini-l">Restricted medical vault</div><b>${m.mode==="enroll"?'Set up an authenticator':'Enter your authenticator code'}</b></div><span class="chip">MFA</span></div>${m.mode==="enroll"?`<p>Open your authenticator app — not your phone's regular Camera app — and choose Add account, then Scan QR code. In Microsoft Authenticator, choose <b>+</b>, <b>Other account</b>, then <b>Scan QR code</b>.</p>${qr}${qrFallback}<div class="codebox medical-secret"><span class="mini-l">Setup key</span><code>${esc(m.secret)}</code></div><p class="note-sm">If this page is open on the same phone, choose manual entry and use the setup key. Keep the default time-based code setting; the app should begin showing a six-digit code that changes periodically.</p>`:`<p>Open your authenticator app and enter its current six-digit code.</p>`}<label for="medical-mfa-code">Six-digit code</label><input id="medical-mfa-code" class="otp-code" type="text" inputmode="numeric" pattern="[0-9]{6}" maxlength="6" autocomplete="one-time-code"><button class="btn sm" ${m.busy?'disabled aria-busy="true"':''} onclick="verifyMedicalMfa('${caseId}')">${m.busy?'Checking…':m.mode==="enroll"?'Enable and open documents':'Verify and open documents'}</button>${m.error?`<div class="banner err">${esc(m.error)}</div>`:""}<p class="note-sm">Authenticator setup stays in memory only and is cleared when you sign out or leave this case.</p>`;
}
function medicalMfaQrSrc(value){
  const qr=typeof value==="string"?value.trim():"";
  const match=/^data:image\/svg\+xml((?:;[^,]*)?),(.*)$/is.exec(qr);if(!match)return "";
  const parameters=match[1].split(";").filter(Boolean).map(v=>v.toLowerCase());
  if(parameters.some(v=>!["utf8","utf-8","charset=utf-8","base64"].includes(v))||parameters.filter(v=>v==="base64").length>1)return "";
  try{
    const payload=match[2],body=parameters.includes("base64")?atob(payload.replace(/\s/g,"")):/^\s*(?:<\?xml|<svg)/i.test(payload)?payload:decodeURIComponent(payload);
    if(!/^\s*(?:<\?xml[^>]*>\s*)?<svg(?:\s|>)/i.test(body))return "";
    return `data:image/svg+xml;charset=utf-8,${encodeURIComponent(body)}`;
  }catch{return "";}
}
function handleMedicalQrError(image){image.hidden=true;const status=image.parentElement?.querySelector(".medical-qr-status");if(status)status.hidden=false;}
function medicalPreviewKind(d){return d?.mimeType==="application/pdf"?"pdf":/^image\/(png|jpeg)$/i.test(d?.mimeType||"")?"image":"download";}
function medicalDocumentHtml(caseId,d,index,permissions){
  const kind=medicalPreviewKind(d);
  return `<div class="task medical-document"><span><b>${esc(d.label||"Medical document")}</b><span class="muted" style="font-size:11px"> · ${esc(d.kind||"document")} · ${fmtBytes(d.sizeBytes)} · ${d.createdAt?fmt(d.createdAt):""}</span>${d.legalHold?'<span class="chip">hold</span>':''}</span><span class="file-actions">${kind!=="download"?`<button id="medical-preview-${index}" class="btn sm sec" onclick="previewMedicalDocument('${caseId}','${esc(d.id)}',this.id)">Preview</button>`:""}<button class="btn sm ghost" onclick="downloadMedicalDocument('${caseId}','${esc(d.id)}')">Download</button>${permissions.retention?`<button class="btn sm ghost" onclick="toggleMedicalLegalHold('${caseId}','${esc(d.id)}',${!d.legalHold})">${d.legalHold?'Release hold':'Place hold'}</button>`:""}</span></div>`;
}
function medicalReturnRequestsHtml(caseId){
  const inv=medicalPanel.invite;
  // T136: shared directory lookup fills the recipient email (accommodation flow).
  registerEmployeeLookup("med-invite", {
    ariaLabel:"Search employees for the document recipient",
    placeholder:"Fill the recipient from the employee directory (optional)…",
    getSelected: () => null,
    onPick: d => { if(d.email){ setMedicalInviteField("email", d.email); paintMedicalPanel(); } else { alert(`${d.name} has no email address in the directory — enter the recipient email manually.`); elRepaint("med-invite"); } },
  });
  return `<div class="divider"></div><div class="medical-section-head"><b>Request documents from employee</b><span class="chip">verified recipient</span></div><p class="note-sm">The invitation is bound to this case, expires, and opens only for the signed-in recipient email. “Requested by” is an administrative follow-up date, not a legal deadline, and passing it does not automatically deny a request.</p>${employeeLookupHtml("med-invite")}<div class="row"><div class="col"><span class="mini-l">Recipient email</span><input id="medical-invite-email" type="email" value="${esc(inv.email)}" autocomplete="off" oninput="setMedicalInviteField('email',this.value)"></div><div class="col"><span class="mini-l">Document purpose</span><select id="medical-invite-kind" onchange="setMedicalInviteField('kind',this.value)"><option value="accommodation" ${inv.kind==='accommodation'?'selected':''}>Accommodation</option><option value="fmla" ${inv.kind==='fmla'?'selected':''}>Medical leave (FMLA)</option></select></div><div class="col"><span class="mini-l">Requested by (days)</span><input id="medical-invite-days" type="number" min="${inv.kind==='fmla'?15:1}" max="90" value="${esc(inv.dueDays)}" oninput="setMedicalInviteField('dueDays',this.value)"></div><div class="col"><span class="mini-l">Or requested-by date</span><input id="medical-invite-date" type="date" value="${esc(inv.dueAt)}" oninput="setMedicalInviteField('dueAt',this.value)"></div></div><span class="mini-l">Message (optional)</span><textarea id="medical-invite-message" maxlength="1000" oninput="setMedicalInviteField('message',this.value)">${esc(inv.message)}</textarea><button class="btn sm" ${inv.busy?'disabled aria-busy="true"':''} onclick="createMedicalReturnRequest('${caseId}')">${inv.busy?'Creating…':'Create secure return request'}</button><p class="note-sm">The employee may return a provider letter or another supported document. No blank form or signature is required by this screen.</p>${inv.error?`<div class="banner err">${esc(inv.error)}</div>`:""}${inv.status?`<div class="banner ok">${esc(inv.status)}</div>`:""}
    ${medicalPanel.returnRequests.length?`<div class="medical-request-list">${medicalPanel.returnRequests.map(r=>medicalReturnRequestRowHtml(caseId,r)).join("")}</div>`:""}`;
}
function medicalReturnRequestRowHtml(caseId,r){
  const inv=medicalPanel.invite;
  const edit=medicalPanel.editingDueDate?.requestId===r.id?medicalPanel.editingDueDate:null;
  const active=["queued","sent"].includes(r.status);
  const formLine=r.formSentAt?` · form sent ${fmt(r.formSentAt)}`:r.formType?" · form send queued":"";
  const info=`${esc(r.status||"")} · ${r.dueAt?'due '+fmt(r.dueAt):'due date sets when sent'}${formLine} · expires ${r.expiresAt?fmt(r.expiresAt):'—'}`;
  const controls=[
    active&&!r.formSentAt&&!r.formType?`<select id="medical-form-type-${esc(r.id)}" aria-label="Blank form to send" onchange="setMedicalInviteField('formType',this.value)"><option value="medical" ${inv.formType==='medical'?'selected':''}>Medical form</option><option value="religious" ${inv.formType==='religious'?'selected':''}>Religious form</option></select><button class="btn sm sec" onclick="sendMedicalReturnForm('${caseId}','${esc(r.id)}')">Send form</button>`:"",
    r.status==="sent"&&!edit?`<button class="btn sm ghost" onclick="startMedicalDueDateEdit('${caseId}','${esc(r.id)}')">Edit due date</button>`:"",
    ["queued","sent","returned"].includes(r.status)?`<button class="btn sm ghost" onclick="resendMedicalReturnRequest('${caseId}','${esc(r.id)}')">Resend</button>`:"",
    active?`<button class="btn sm ghost" onclick="revokeMedicalReturnRequest('${caseId}','${esc(r.id)}')">Revoke</button>`:"",
  ].join("");
  const editor=edit?`<div class="task medical-due-edit"><span><span class="mini-l">New requested-by date</span></span><span class="file-actions"><input id="medical-due-input-${esc(r.id)}" type="date" aria-label="New requested-by date" value="${esc(edit.value)}" oninput="setMedicalDueDateValue(this.value)"><button class="btn sm" ${edit.busy?'disabled aria-busy="true"':''} onclick="saveMedicalDueDate('${caseId}','${esc(r.id)}')">${edit.busy?'Saving…':'Save date'}</button><button class="btn sm ghost" onclick="cancelMedicalDueDateEdit()">Cancel</button></span></div>${edit.error?`<div class="banner err">${esc(edit.error)}</div>`:""}`:"";
  return `<div class="task"><span><b>${esc(r.recipientMasked||"Recipient")}</b><span class="muted" style="font-size:11px"> · ${info}</span></span><span class="file-actions">${controls}</span></div>${editor}`;
}
const MEDICAL_AUDIT_ACTIONS={list:"Document list opened",signed_url_issued:"File access authorized",upload_prepared:"Upload started",upload_committed:"Document uploaded",return_committed:"Employee document returned",invite_created:"Document request created",invite_resent:"Document request resent",invite_redeemed:"Secure request opened",delivery_confirmed:"Request email sent",form_sent:"Blank form sent",invite_revoked:"Secure request revoked",due_date_overridden:"Requested-by date changed",legal_hold_set:"Legal hold placed",legal_hold_released:"Legal hold released",retention_previewed:"Retention review previewed",retention_queued:"Retention review queued",retention_policy_changed:"Retention policy changed"};
function medicalAuditTime(value){if(!value)return "Time unavailable";const d=new Date(value);if(Number.isNaN(d.getTime()))return "Time unavailable";return new Intl.DateTimeFormat(undefined,{year:"numeric",month:"short",day:"numeric",hour:"numeric",minute:"2-digit",timeZoneName:"short"}).format(d);}
function medicalAuditEventHtml(e){const outcome=e.outcome==="success"?"Succeeded":e.outcome==="denied"?"Denied":e.outcome==="skipped"?"Skipped":"Recorded";return `<li><div class="t" title="${esc(e.at||"")}">${esc(medicalAuditTime(e.at))} · ${esc(outcome)}</div><div class="e"><b>${esc(MEDICAL_AUDIT_ACTIONS[e.action]||"Medical vault activity")}</b>${e.documentLabel?` · ${esc(e.documentLabel)}`:""}</div><div class="note-sm">${esc(e.actorLabel||"Actor unavailable")}</div></li>`;}
function medicalOperationsHtml(caseId,permissions=medicalPanel.capabilities?.permissions||{}){const a=medicalPanel;return `<div id="medical-operations"><div class="divider"></div><div class="medical-section-head"><b>Medical document access log</b><span class="chip">restricted</span></div><p class="note-sm">Shows activity recorded by the restricted medical service. “File access authorized” means access was approved; it does not prove a preview opened or a download completed.${permissions.retention?' Retention review is a dry run, and queueing does not delete files.':''}</p><div class="medical-audit-controls"><label><span class="mini-l">Activity type</span><select onchange="setMedicalAuditGroup('${caseId}',this.value)"><option value="all" ${a.auditGroup==='all'?'selected':''}>All activity</option><option value="access" ${a.auditGroup==='access'?'selected':''}>Document access</option><option value="uploads" ${a.auditGroup==='uploads'?'selected':''}>Uploads</option><option value="requests" ${a.auditGroup==='requests'?'selected':''}>Employee requests</option><option value="retention" ${a.auditGroup==='retention'?'selected':''}>Retention and holds</option></select></label><button class="btn sm ghost" ${a.auditStatus==='loading'?'disabled aria-busy="true"':''} onclick="loadMedicalAudit('${caseId}',false)">${a.auditStatus==='loading'?'Loading…':a.auditStatus==='ready'?'Refresh log':'Load access log'}</button>${permissions.retention?`<button class="btn sm ghost" onclick="previewMedicalRetention('${caseId}')">Preview retention candidates</button>`:""}</div><div class="medical-audit-result" role="status">${a.auditStatus==='error'?`<div class="banner err">${esc(a.auditError||"The access log could not be loaded.")}</div>`:a.auditStatus==='ready'&&!a.audit.length?'<p class="muted">No recorded activity matches this filter.</p>':a.audit.length?`<ul class="timeline medical-audit">${a.audit.map(medicalAuditEventHtml).join("")}</ul>${a.auditCursor?`<button class="btn sm ghost" ${a.auditStatus==='loading'?'disabled':''} onclick="loadMedicalAudit('${caseId}',true)">Load older activity</button>`:""}`:'<p class="muted">Load the log to review medical document activity.</p>'}</div>${permissions.retention&&a.retention.length?`<div class="medical-retention"><p><b>Dry-run candidates</b></p>${a.retention.map(c=>`<label class="check-line"><input type="checkbox" data-medical-retention-id="${esc(c.id)}"> ${esc(c.id)} · eligible ${c.eligibleAt?fmt(c.eligibleAt):'—'}</label>`).join("")}<button class="btn sm ghost" onclick="enqueueMedicalRetention('${caseId}')">Queue selected for review</button></div>`:""}</div>`;}
function hardenMedicalFileInputs(root=document){root.querySelectorAll?.("#medical-files,#medical-return-files").forEach(input=>input.setAttribute("accept",".pdf,.png,.jpg,.jpeg,.docx"));}
function paintMedicalPanel(){const el=$("medical-panel");if(el&&selected===medicalPanel.caseId){el.innerHTML=medicalPanelShellHtml(medicalPanel.caseId);hardenMedicalFileInputs(el);}}
function paintMedicalOperations(){const el=$("medical-operations");if(el&&selected===medicalPanel.caseId)el.outerHTML=medicalOperationsHtml(medicalPanel.caseId);}
async function loadMedicalPanel(caseId){
  if(!session||selected!==caseId)return;
  if(medicalPanel.caseId!==caseId)medicalPanel=blankMedicalPanel(caseId);
  medicalPanel.status="loading";medicalPanel.error="";medicalPanel.audit=[];medicalPanel.auditStatus="idle";medicalPanel.auditError="";medicalPanel.auditCursor=null;medicalPanel.auditGeneration++;paintMedicalPanel();
  const epoch=sessionEpoch,userId=session.user.id,generation=medicalPanel.generation;
  const cap=await medicalAction({action:"capabilities",caseId});
  if(!medicalCurrent(caseId,generation,epoch,userId))return;
  if(cap.error){const failure=cap.error;medicalPanel=blankMedicalPanel(caseId);medicalPanel.status="error";medicalPanel.error=failure;paintMedicalPanel();return;}
  medicalPanel.capabilities=cap.data;const listed=await medicalAction({action:"list",caseId});
  if(!medicalCurrent(caseId,generation,epoch,userId))return;
  if(listed.error){medicalPanel.documents=[];medicalPanel.returnRequests=[];medicalPanel.capabilities=null;medicalPanel.audit=[];medicalPanel.auditCursor=null;medicalPanel.status="error";medicalPanel.error=listed.error;paintMedicalPanel();return;}
  medicalPanel.documents=listed.data?.documents||[];medicalPanel.returnRequests=listed.data?.returnRequests||[];medicalPanel.status="ready";medicalPanel.error="";paintMedicalPanel();
}
async function startMedicalMfa(caseId){
  if(selected!==caseId||medicalPanel.error?.code!=="MFA_REQUIRED"||medicalPanel.mfa.busy)return;
  const epoch=sessionEpoch,userId=session?.user?.id,generation=medicalPanel.generation;mfaBusy(true);
  try{
    const factors=await sb.auth.mfa.listFactors();if(!medicalCurrent(caseId,generation,epoch,userId))return;
    if(factors.error){mfaBusy(false,"Authenticator setup could not be checked. Try again.");return;}
    const factor=(factors.data?.totp||[]).find(f=>f.status==="verified");
    if(factor){medicalPanel.mfa={mode:"challenge",factorId:factor.id,qr:"",secret:"",error:"",busy:false};paintMedicalPanel();return;}
    const stale=(factors.data?.all||[]).filter(f=>f.factor_type==="totp"&&f.status==="unverified"&&f.friendly_name==="People Support medical documents");
    for(const pending of stale){const removed=await sb.auth.mfa.unenroll({factorId:pending.id});if(!medicalCurrent(caseId,generation,epoch,userId))return;if(removed.error){mfaBusy(false,"An earlier authenticator setup could not be reset. Try again.");return;}}
    const enrolled=await sb.auth.mfa.enroll({factorType:"totp",friendlyName:"People Support medical documents",issuer:"People Support Portal"});
    if(!medicalCurrent(caseId,generation,epoch,userId))return;
    if(enrolled.error){mfaBusy(false,"Authenticator setup could not be started. Try again.");return;}
    const factorId=enrolled.data?.id||"",qr=enrolled.data?.totp?.qr_code||"",secret=enrolled.data?.totp?.secret||"";
    if(!factorId||!secret){mfaBusy(false,"Authenticator setup details were unavailable. Try again.");return;}
    medicalPanel.mfa={mode:"enroll",factorId,qr,secret,error:"",busy:false};paintMedicalPanel();
  }catch{if(medicalCurrent(caseId,generation,epoch,userId))mfaBusy(false,"Authenticator setup could not be started. Check your connection and try again.");}
}
function mfaBusy(busy,error=""){medicalPanel.mfa.busy=busy;medicalPanel.mfa.error=error;paintMedicalPanel();}
async function verifyMedicalMfa(caseId){
  if(!session||selected!==caseId||medicalPanel.caseId!==caseId||medicalPanel.mfa.busy)return;
  const code=($("medical-mfa-code")?.value||"").trim();if(!/^\d{6}$/.test(code)){mfaBusy(false,"Enter the six-digit code from your authenticator app.");return;}
  const factorId=medicalPanel.mfa.factorId;if(!factorId){medicalPanel.mfa={mode:"",factorId:"",qr:"",secret:"",error:"Authenticator setup expired. Start the identity check again.",busy:false};paintMedicalPanel();return;}
  const epoch=sessionEpoch,userId=session?.user?.id,generation=medicalPanel.generation;mfaBusy(true);
  let verified;try{verified=await sb.auth.mfa.challengeAndVerify({factorId,code});}catch{if(medicalCurrent(caseId,generation,epoch,userId))mfaBusy(false,"The authenticator service could not be reached. Check your connection and try again.");return;}
  if(!medicalCurrent(caseId,generation,epoch,userId))return;
  if(verified.error){mfaBusy(false,"That authenticator code did not work. Try the current code.");return;}
  medicalPanel.mfa={mode:"",factorId:"",qr:"",secret:"",error:"",busy:false};medicalPanel.status="idle";await loadMedicalPanel(caseId);
}
function medicalFileInfo(file){const ext=String(file?.name||"").split(".").pop().toLowerCase(),type=String(file?.type||"").toLowerCase(),allowed=MEDICAL_FILE_RULES.mimeByExtension[ext]||[];return {ext,type:type||allowed[0]||"",valid:!!allowed.length&&(!type||allowed.includes(type))&&file.size>0&&file.size<=MEDICAL_FILE_RULES.maxBytes};}
function setMedicalFiles(files){medicalPanel.files=Array.from(files||[]);medicalPanel.error="";}
async function uploadMedicalFiles(caseId){
  const files=[...medicalPanel.files];if(!files.length){medicalPanel.status="upload-error";medicalPanel.error={message:"Choose at least one PDF, image, Word document."};paintMedicalPanel();return;}
  const invalid=files.find(f=>!medicalFileInfo(f).valid);if(invalid){medicalPanel.status="upload-error";medicalPanel.error={message:`${invalid.name} is empty, too large, or has an unsupported file type.`};paintMedicalPanel();return;}
  const kind=$("medical-kind")?.value||"other",label=($("medical-label")?.value||"").trim();const epoch=sessionEpoch,userId=session?.user?.id,generation=medicalPanel.generation;medicalPanel.busy=true;paintMedicalPanel();
  try{for(const file of files){const info=medicalFileInfo(file),requestId=crypto.randomUUID();const prepared=await medicalAction({action:"prepare_upload",caseId,requestId,file:{name:file.name,type:info.type,size:file.size},kind,...(label?{label}:{} )});if(!medicalCurrent(caseId,generation,epoch,userId))return;if(prepared.error)throw prepared.error;const upload=prepared.data?.file;if(!upload?.bucket||!upload?.uploadPath||!upload?.token)throw new Error("The private upload authorization was unavailable.");const uploaded=await sb.storage.from(upload.bucket).uploadToSignedUrl(upload.uploadPath,upload.token,file,{contentType:info.type});if(!medicalCurrent(caseId,generation,epoch,userId))return;if(uploaded.error)throw uploaded.error;const committed=await medicalAction({action:"commit_upload",caseId,requestId,uploadId:prepared.data.uploadId});if(!medicalCurrent(caseId,generation,epoch,userId))return;if(committed.error)throw committed.error;}medicalPanel.files=[];medicalPanel.busy=false;medicalPanel.status="idle";await loadMedicalPanel(caseId);}catch(error){if(medicalCurrent(caseId,generation,epoch,userId)){medicalPanel.busy=false;medicalPanel.status="upload-error";medicalPanel.error={message:error?.message||"Upload failed. Retry from the original file."};paintMedicalPanel();}}
}
function findMedicalDocument(id){return medicalPanel.documents.find(d=>d.id===id);}
async function authorizeMedicalDocument(caseId,documentId,disposition){const result=await medicalAction({action:"download",caseId,documentId,disposition});return {url:result.data?.url,error:result.error,note:"Restricted preview access expires after one minute."};}
async function previewMedicalDocument(caseId,documentId,restoreId){const source=medicalPanel,generation=source.generation,d=findMedicalDocument(documentId);if(!d)return;await openAttachmentPreview({name:d.label||"Medical document",type:d.mimeType||"",kindOverride:medicalPreviewKind(d),restoreId,isCurrent:()=>selected===caseId&&medicalPanel===source&&medicalPanel.generation===generation&&!!findMedicalDocument(documentId),authorize:()=>authorizeMedicalDocument(caseId,documentId,"inline"),download:()=>downloadMedicalDocument(caseId,documentId)});}
async function downloadMedicalDocument(caseId,documentId){const epoch=sessionEpoch,userId=session?.user?.id,generation=medicalPanel.generation,result=await authorizeMedicalDocument(caseId,documentId,"attachment");if(!medicalCurrent(caseId,generation,epoch,userId)||!findMedicalDocument(documentId))return;if(!result.url){alert("Could not authorize this restricted download: "+(result.error?.message||"unknown error"));return;}const a=document.createElement("a");a.href=result.url;a.target="_blank";a.rel="noopener noreferrer";a.referrerPolicy="no-referrer";document.body.appendChild(a);a.click();a.remove();}
function setMedicalInviteField(field,value){if(!["email","kind","dueDays","dueAt","message","formType"].includes(field))return;if(field==="formType"&&!["medical","religious"].includes(value))return;medicalPanel.invite[field]=value;if(field==="kind"&&value==="fmla"&&Number(medicalPanel.invite.dueDays)<15)medicalPanel.invite.dueDays="15";medicalPanel.invite.error="";medicalPanel.invite.status="";medicalPanel.invite.idempotencyKey="";if(field==="kind")paintMedicalPanel();}
async function createMedicalReturnRequest(caseId){const inv=medicalPanel.invite,email=inv.email.trim().toLowerCase(),days=Number(inv.dueDays);if(!/^\S+@\S+\.\S+$/.test(email)){inv.error="Enter the recipient's email address.";paintMedicalPanel();return;}if(inv.kind==="fmla"&&!inv.dueAt&&(!Number.isFinite(days)||days<15)){inv.error="Medical leave requests need a requested-by date or at least 15 days.";paintMedicalPanel();return;}inv.busy=true;inv.error="";inv.status="";inv.idempotencyKey||=crypto.randomUUID();paintMedicalPanel();const epoch=sessionEpoch,userId=session?.user?.id,generation=medicalPanel.generation;const result=await medicalAction({action:"create_return_request",caseId,recipientEmail:email,requestKind:inv.kind,...(inv.dueAt?{dueAt:new Date(inv.dueAt+"T12:00:00Z").toISOString()}:{dueDays:days||14}),...(inv.message.trim()?{message:inv.message.trim()}:{}),idempotencyKey:inv.idempotencyKey});if(!medicalCurrent(caseId,generation,epoch,userId))return;inv.busy=false;if(result.error){inv.error=result.error.message||"The request could not be created.";paintMedicalPanel();return;}inv.status="Secure request queued. Its requested-by date will be set when delivery succeeds.";inv.idempotencyKey="";medicalPanel.returnRequests=[result.data?.request,...medicalPanel.returnRequests].filter(Boolean);paintMedicalPanel();}
async function resendMedicalReturnRequest(caseId,returnRequestId){const epoch=sessionEpoch,userId=session?.user?.id,generation=medicalPanel.generation,result=await medicalAction({action:"resend_return_request",caseId,returnRequestId,idempotencyKey:crypto.randomUUID()});if(!medicalCurrent(caseId,generation,epoch,userId))return;if(result.error){medicalPanel.invite.error=result.error.message||"The request could not be resent.";}else medicalPanel.invite.status="Resend queued. The original due date is preserved.";paintMedicalPanel();}
function updateMedicalReturnRow(returnRequestId,request){const index=medicalPanel.returnRequests.findIndex(r=>r.id===returnRequestId);if(index>=0&&request)medicalPanel.returnRequests[index]={...medicalPanel.returnRequests[index],...request};}
async function sendMedicalReturnForm(caseId,returnRequestId){
  const inv=medicalPanel.invite,formType=inv.formType;
  if(!["medical","religious"].includes(formType)){inv.error="Choose the medical or religious accommodation form first.";paintMedicalPanel();return;}
  inv.error="";inv.status="";
  const epoch=sessionEpoch,userId=session?.user?.id,generation=medicalPanel.generation;
  const result=await medicalAction({action:"send_return_form",caseId,returnRequestId,formType,idempotencyKey:crypto.randomUUID()});
  if(!medicalCurrent(caseId,generation,epoch,userId))return;
  if(result.error){
    const code=result.error.code;
    medicalPanel.invite.error=code==="ALREADY_SENT"?"A blank form was already sent for this request.":code==="ALREADY_TERMINAL"?"This request is no longer active.":result.error.message||"The form could not be sent.";
  }else{
    updateMedicalReturnRow(returnRequestId,result.data?.request);
    medicalPanel.invite.status="Blank form queued for delivery with the secure return link.";
  }
  paintMedicalPanel();
}
async function revokeMedicalReturnRequest(caseId,returnRequestId){
  const reason=prompt("Reason for revoking this secure request:","");
  if(reason===null||!reason.trim())return;
  medicalPanel.invite.error="";medicalPanel.invite.status="";
  const epoch=sessionEpoch,userId=session?.user?.id,generation=medicalPanel.generation;
  const result=await medicalAction({action:"revoke_return_request",caseId,returnRequestId,reason:reason.trim()});
  if(!medicalCurrent(caseId,generation,epoch,userId))return;
  if(result.error){
    const code=result.error.code;
    medicalPanel.invite.error=code==="ALREADY_TERMINAL"?"This request has already ended (returned, revoked, or expired).":result.error.message||"The request could not be revoked.";
  }else{
    updateMedicalReturnRow(returnRequestId,result.data?.request);
    if(medicalPanel.editingDueDate?.requestId===returnRequestId)medicalPanel.editingDueDate=null;
    medicalPanel.invite.status="The secure request was revoked. Its link no longer works; the employee is not notified.";
  }
  paintMedicalPanel();
}
function startMedicalDueDateEdit(caseId,returnRequestId){
  if(medicalPanel.caseId!==caseId)return;
  const r=medicalPanel.returnRequests.find(x=>x.id===returnRequestId);
  if(!r||r.status!=="sent")return;
  medicalPanel.editingDueDate={requestId:returnRequestId,value:r.dueAt?String(r.dueAt).slice(0,10):"",error:"",busy:false};
  paintMedicalPanel();
}
function setMedicalDueDateValue(value){if(medicalPanel.editingDueDate)medicalPanel.editingDueDate.value=value;}
function cancelMedicalDueDateEdit(){medicalPanel.editingDueDate=null;paintMedicalPanel();}
async function saveMedicalDueDate(caseId,returnRequestId){
  const edit=medicalPanel.editingDueDate;
  if(!edit||edit.requestId!==returnRequestId||edit.busy)return;
  const value=(edit.value||"").trim();
  if(!/^\d{4}-\d{2}-\d{2}$/.test(value)){edit.error="Enter a valid date.";paintMedicalPanel();return;}
  const dueAt=new Date(value+"T12:00:00Z").toISOString();
  edit.busy=true;edit.error="";paintMedicalPanel();
  const epoch=sessionEpoch,userId=session?.user?.id,generation=medicalPanel.generation;
  const result=await medicalAction({action:"update_return_due_date",caseId,returnRequestId,dueAt});
  if(!medicalCurrent(caseId,generation,epoch,userId))return;
  const current=medicalPanel.editingDueDate;
  if(!current||current.requestId!==returnRequestId)return;
  current.busy=false;
  if(result.error){
    const code=result.error.code;
    current.error=code==="INVALID_DUE_DATE"?"Choose a future date. Medical leave (FMLA) requests need at least 15 days from first send.":code==="ALREADY_TERMINAL"?"This request is no longer active.":result.error.message||"The due date could not be updated.";
    paintMedicalPanel();return;
  }
  updateMedicalReturnRow(returnRequestId,result.data?.request);
  medicalPanel.editingDueDate=null;
  medicalPanel.invite.status="The requested-by date was updated.";
  paintMedicalPanel();
}
async function toggleMedicalLegalHold(caseId,documentId,enabled){const reason=prompt(enabled?"Reason for placing this document on hold:":"Reason for releasing this document hold:","");if(reason===null||!reason.trim())return;const epoch=sessionEpoch,userId=session?.user?.id,generation=medicalPanel.generation,result=await medicalAction({action:"set_legal_hold",caseId,documentId,enabled,reason:reason.trim()});if(!medicalCurrent(caseId,generation,epoch,userId))return;if(result.error){alert(result.error.message||"The hold could not be updated.");return;}const index=medicalPanel.documents.findIndex(d=>d.id===documentId);if(index>=0)medicalPanel.documents[index]={...medicalPanel.documents[index],...(result.data||{}),legalHold:enabled};paintMedicalPanel();}
function setMedicalAuditGroup(caseId,group){if(!["all","access","uploads","requests","retention"].includes(group)||medicalPanel.caseId!==caseId)return;medicalPanel.auditGroup=group;medicalPanel.audit=[];medicalPanel.auditCursor=null;medicalPanel.auditStatus="idle";medicalPanel.auditError="";medicalPanel.auditGeneration++;paintMedicalOperations();void loadMedicalAudit(caseId,false);}
async function loadMedicalAudit(caseId,append=false){if(medicalPanel.auditStatus==="loading")return;const epoch=sessionEpoch,userId=session?.user?.id,generation=medicalPanel.generation,group=medicalPanel.auditGroup,beforeId=append?medicalPanel.auditCursor:null,auditGeneration=++medicalPanel.auditGeneration;medicalPanel.auditStatus="loading";medicalPanel.auditError="";if(!append){medicalPanel.audit=[];medicalPanel.auditCursor=null;}paintMedicalOperations();const result=await medicalAction({action:"audit_list",caseId,limit:25,group,...(beforeId?{beforeId}:{})});if(!medicalCurrent(caseId,generation,epoch,userId)||medicalPanel.auditGroup!==group||medicalPanel.auditGeneration!==auditGeneration)return;if(result.error){if(["AUTH_REQUIRED","MFA_REQUIRED","CASE_UNAVAILABLE","NOT_MEDICAL_STAFF"].includes(result.error.code)){medicalPanel=blankMedicalPanel(caseId);medicalPanel.status="error";medicalPanel.error=result.error;paintMedicalPanel();return;}medicalPanel.audit=[];medicalPanel.auditCursor=null;medicalPanel.auditStatus="error";medicalPanel.auditError=result.error.message||"The access log could not be loaded.";paintMedicalOperations();return;}medicalPanel.audit=append?[...medicalPanel.audit,...(result.data?.events||[])]:result.data?.events||[];medicalPanel.auditCursor=result.data?.nextCursor||null;medicalPanel.auditStatus="ready";paintMedicalOperations();}
async function previewMedicalRetention(caseId){const epoch=sessionEpoch,userId=session?.user?.id,generation=medicalPanel.generation,result=await medicalAction({action:"retention_preview",caseId,limit:100});if(!medicalCurrent(caseId,generation,epoch,userId))return;if(result.error){alert(result.error.message||"Retention preview could not be loaded.");return;}medicalPanel.retention=result.data?.candidates||[];paintMedicalPanel();}
async function enqueueMedicalRetention(caseId){const ids=[...document.querySelectorAll("[data-medical-retention-id]:checked")].map(el=>el.dataset.medicalRetentionId).filter(Boolean);if(!ids.length){alert("Select at least one dry-run candidate.");return;}const reason=prompt("Reason for queueing these records for retention review:","");if(reason===null||!reason.trim())return;const epoch=sessionEpoch,userId=session?.user?.id,generation=medicalPanel.generation,result=await medicalAction({action:"retention_enqueue",caseId,documentIds:ids,reason:reason.trim()});if(!medicalCurrent(caseId,generation,epoch,userId))return;if(result.error){alert(result.error.message||"The retention review could not be queued.");return;}alert(`${result.data?.queued?.length||0} document(s) queued for review. No files were deleted.`);await previewMedicalRetention(caseId);}

function evidenceHtml(caseId){
  if(evidence.err) return `<span class="muted">${esc(evidence.err)}</span>`;
  if(!evidence.list.length) return '<span class="muted">No evidence uploaded.</span>';
  return evidence.list.map((f,index)=>{const display=f.name.replace(/^\d+_/,''),kind=attachmentKind(display,f.metadata?.mimetype||"");return `<div class="task"><span>${esc(display)}</span>
      <span class="due">${f.created_at?fmt(f.created_at):''}</span>
      <span class="file-actions">${kind!=="download"?`<button id="evidence-preview-${index}" class="btn sm sec" data-n="${esc(f.name)}" data-d="${esc(display)}" data-t="${esc(f.metadata?.mimetype||'')}" onclick="evPreview('${caseId}',this.dataset.n,this.dataset.d,this.dataset.t,this.id)">Preview</button>`:""}<button class="btn sm ghost" data-n="${esc(f.name)}" onclick="evDownload('${caseId}',this.dataset.n)">Download</button></span></div>`;}).join("")
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
  const caseId=selected,epoch=sessionEpoch,userId=session?.user?.id,source=caseExport;
  const linked=source?.c?.id===caseId&&(source.files||[]).some(file=>file.storage_path===path&&file.file_name===name);
  if(!caseId||!linked||!caseFilePathAllowed({storage_path:path,source:"email"},caseId)){alert("This file is not linked to the open case.");return;}
  const { data, error } = await sb.storage.from("evidence").download(path);
  if(epoch!==sessionEpoch||session?.user?.id!==userId||selected!==caseId||caseExport!==source||!(source.files||[]).some(file=>file.storage_path===path&&file.file_name===name))return;
  if(error || !data){ alert("Could not download this file: " + (error?.message||"unknown error")); return; }
  downloadBlob(data, name || path.split("/").pop());
}
async function caseFilePreview(path,name,type,restoreId){
  const caseId=selected;
  const linked=caseExport?.c?.id===caseId&&(caseExport.files||[]).some(file=>file.storage_path===path&&file.file_name===name);
  if(!caseId || !linked || !caseFilePathAllowed({storage_path:path,source:"email"},caseId)){alert("This file is not linked to the open case.");return;}
  await openAttachmentPreview({name,type,restoreId,
    isCurrent:()=>selected===caseId&&caseExport?.c?.id===caseId&&(caseExport.files||[]).some(file=>file.storage_path===path&&file.file_name===name),
    authorize:async()=>{const {data,error}=await sb.storage.from("evidence").createSignedUrl(path,120);return {url:data?.signedUrl,error,note:"Private preview access expires after two minutes."};},
    download:()=>caseFileDownload(path,name)});
}
async function evDownload(caseId, fname){
  if(selected!==caseId||!fname||/[\\/]/.test(fname)||!evidence.list.some(file=>file.name===fname)){alert("This evidence file is not linked to the open case.");return;}
  const epoch=sessionEpoch,userId=session?.user?.id,source=evidence;
  const { data, error } = await sb.storage.from("evidence").createSignedUrl(`${caseId}/${fname}`, 120);
  if(epoch!==sessionEpoch||session?.user?.id!==userId||selected!==caseId||evidence!==source||!source.list.some(file=>file.name===fname))return;
  if(error || !data?.signedUrl){ alert("Could not create a download link: " + (error?.message||"unknown error")); return; }
  window.open(data.signedUrl, "_blank");
}
async function evPreview(caseId,fname,displayName,type,restoreId){
  if(selected!==caseId || !fname || /[\\/]/.test(fname) || !evidence.list.some(file=>file.name===fname)){alert("This evidence file path is invalid.");return;}
  const path=`${caseId}/${fname}`;
  await openAttachmentPreview({name:displayName||fname,type,restoreId,
    isCurrent:()=>selected===caseId&&evidence.list.some(file=>file.name===fname),
    authorize:async()=>{const {data,error}=await sb.storage.from("evidence").createSignedUrl(path,120);return {url:data?.signedUrl,error,note:"Private preview access expires after two minutes."};},
    download:()=>evDownload(caseId,fname)});
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
const INTERVIEW_FORMATS = ["Virtual", "Phone", "In person"];
function browserTimeZone(){ try{return Intl.DateTimeFormat().resolvedOptions().timeZone||"UTC";}catch{return "UTC";} }
// T135 (Ops/People 9/15): the zone dropdown offers Pacific / Central / Eastern
// only. Values stay full IANA names (DB contract); a legacy stored zone outside
// the trio remains selectable so old rows stay truthful.
const INTERVIEW_TIMEZONES = [
  ["America/Los_Angeles","Pacific (PST/PDT)"],
  ["America/Chicago","Central (CST/CDT)"],
  ["America/New_York","Eastern (EST/EDT)"],
];
const TZ_SHORT = { "America/Los_Angeles":"PT", "America/Chicago":"CT", "America/New_York":"ET", UTC:"UTC" };
// Wall-clock display: the stored local time is shown as entered (12-hour) with
// its zone — never converted through the viewer's browser zone.
function fmtLocalTime(time,zone){
  if(!time) return "Time not recorded";
  const [h,m]=String(time).split(":");
  const hour=Number(h);
  const label=`${((hour+11)%12)+1}:${m} ${hour<12?"AM":"PM"}`;
  if(!zone) return label;
  return TZ_SHORT[zone] ? `${label} ${TZ_SHORT[zone]} (${zone})` : `${label} ${zone}`;
}
function timezoneSelectHtml(id,value){
  const options=[...INTERVIEW_TIMEZONES];
  if(value&&!options.some(([zone])=>zone===value)) options.unshift([value,`${value} (legacy)`]);   // stored zone outside PT/CT/ET stays selectable, flagged as legacy
  return `<select id="${id}"><option value="">Not recorded</option>${options.map(([zone,label])=>`<option value="${esc(zone)}" ${zone===value?'selected':''}>${esc(label)}</option>`).join("")}</select>`;
}
function interviewPairs(value){
  if(typeof value==="string") try{value=JSON.parse(value);}catch{return [];}
  return Array.isArray(value)?value.filter(pair=>pair&&typeof pair==="object").map(pair=>({id:String(pair.id||crypto.randomUUID()),question:String(pair.question||""),response:String(pair.response||"")})):[];
}
// T135: per-interview contact-attempt log ({id, at, note}; migration 20260915 adds the column)
function interviewAttempts(value){
  if(typeof value==="string") try{value=JSON.parse(value);}catch{return [];}
  return Array.isArray(value)?value.filter(a=>a&&typeof a==="object").map(a=>({id:String(a.id||crypto.randomUUID()),at:String(a.at||""),note:String(a.note||"")})):[];
}
// a, b, … z, aa, ab, … — the per-case enumeration suffix (EB-2026-0143a style)
function exportSuffix(index){
  let s="",n=index;
  do { s=String.fromCharCode(97+(n%26))+s; n=Math.floor(n/26)-1; } while(n>=0);
  return s;
}
const interviewCode = (snapshot,id) => {
  const index=(snapshot?.interviews||[]).findIndex(item=>item.id===id);
  return index<0?"":`${snapshot?.c?.ref||"case"}${exportSuffix(index)}`;
};
const interviewBoilerplateHtml = () =>
  `<div class="iv-boilerplate"><span class="mini-l">Interview introduction — read to the interviewee before the first question</span>${ER_STATEMENT_GUIDE.script.map(line=>`<p>${esc(line)}</p>`).join("")}</div>`;
function interviewDraft(iv){
  if(!interviewDrafts.has(iv.id)) interviewDrafts.set(iv.id,{
    id:iv.id, interviewee:iv.interviewee||"", role:iv.role_in_case||"", date:iv.interview_date||"",
    time:iv.interview_local_time||"", timezone:iv.interview_timezone||"", format:iv.interview_format||"",
    duration:iv.duration_minutes==null?"":String(iv.duration_minutes), title:iv.interviewee_title||"",
    location:iv.interviewee_location||"", interviewer:iv.interviewer||"", status:iv.status||"Scheduled",
    notes:iv.notes||"", followUp:iv.follow_up||"", opening:iv.opening_response||"",
    closing:iv.closing_response||"", pairs:interviewPairs(iv.question_responses),
    attempts:interviewAttempts(iv.contact_attempts), savedAttempts:interviewAttempts(iv.contact_attempts), caNew:""
  });
  return interviewDrafts.get(iv.id);
}
function interviewEditorHtml(caseId,iv){
  const d=interviewDraft(iv);
  const code=interviewCode(caseExport,iv.id);
  return `<div class="iv-row" id="iv-${iv.id}">
    ${code?`<div style="margin-bottom:8px"><span class="chip">${esc(code)}</span></div>`:""}
    <div class="iv-grid">
      <span><span class="mini-l">Person interviewed</span><input id="iv-name-${iv.id}" type="text" value="${esc(d.interviewee)}" oninput="syncInterviewDraft('${iv.id}')"></span>
      <span><span class="mini-l">Role in case</span><select id="iv-role-${iv.id}" onchange="syncInterviewDraft('${iv.id}')">${[...new Set([...PARTY_ROLES,...(d.role?[d.role]:[]),"Other"])].map(r=>`<option value="${esc(r)}" ${d.role===r?'selected':''}>${esc(rlabel(r))}</option>`).join("")}</select></span>
      <span><span class="mini-l">Date</span><input id="iv-date-${iv.id}" type="date" value="${esc(d.date)}" oninput="syncInterviewDraft('${iv.id}')"></span>
      <span><span class="mini-l">Local time</span><input id="iv-time-${iv.id}" type="time" step="60" value="${esc(String(d.time).slice(0,5))}" oninput="syncInterviewDraft('${iv.id}')">${d.time?'':'<span class="note-sm">Time not recorded</span>'}</span>
      <span><span class="mini-l">Time zone</span>${timezoneSelectHtml(`iv-zone-${iv.id}`,d.time?d.timezone:"").replace('<select ',`<select onchange="syncInterviewDraft('${iv.id}')" `)}</span>
      <span><span class="mini-l">Format</span><select id="iv-format-${iv.id}" onchange="syncInterviewDraft('${iv.id}')"><option value="">Not recorded</option>${INTERVIEW_FORMATS.map(v=>`<option ${d.format===v?'selected':''}>${v}</option>`).join("")}</select></span>
      <span><span class="mini-l">Duration (minutes)</span><input id="iv-duration-${iv.id}" type="number" min="1" max="1440" value="${esc(d.duration)}" oninput="syncInterviewDraft('${iv.id}')"></span>
      <span><span class="mini-l">Interviewee title</span><input id="iv-title-${iv.id}" type="text" value="${esc(d.title)}" oninput="syncInterviewDraft('${iv.id}')"></span>
      <span><span class="mini-l">Interviewee location</span><input id="iv-location-${iv.id}" type="text" value="${esc(d.location)}" oninput="syncInterviewDraft('${iv.id}')"></span>
      <span><span class="mini-l">Interviewer</span><input id="iv-by-${iv.id}" type="text" value="${esc(d.interviewer)}" oninput="syncInterviewDraft('${iv.id}')"></span>
      <span><span class="mini-l">Status</span><select id="iv-status-${iv.id}" onchange="syncInterviewDraft('${iv.id}')">${INTERVIEW_STATUS.map(s=>`<option ${d.status===s?'selected':''}>${s}</option>`).join("")}</select></span>
      <span><span class="mini-l">Follow-up needed</span><input id="iv-fu-${iv.id}" type="text" value="${esc(d.followUp)}" oninput="syncInterviewDraft('${iv.id}')"></span>
    </div>
    <div class="iv-attempts" aria-label="Contact attempts">
      <span class="mini-l">Contact attempts</span>
      ${d.attempts.length?d.attempts.map((a,index)=>`<div class="iv-attempt"><span class="iv-attempt-at">${esc(fmt(a.at)||"—")}</span><span class="iv-attempt-note">${esc(a.note)}</span><button class="btn sm ghost" onclick="removeInterviewContactAttempt('${caseId}','${iv.id}',${index})" aria-label="Remove contact attempt ${index+1}">×</button></div>`).join(""):'<span class="muted" style="font-size:12px">No contact attempts logged.</span>'}
      <div class="iv-attempt-add"><input id="iv-ca-new-${iv.id}" type="text" maxlength="500" value="${esc(d.caNew||"")}" placeholder="e.g. Called 3x, no answer — left voicemail" oninput="syncInterviewDraft('${iv.id}')"><button class="btn sm ghost" onclick="logInterviewContactAttempt('${caseId}','${iv.id}')">Log attempt</button></div>
      <span class="note-sm">Each attempt is stamped with the current date and time and saved immediately. Attempts appear in the case export.</span>
    </div>
    ${interviewBoilerplateHtml()}
    <label class="mini-l" for="iv-opening-${iv.id}" style="margin-top:10px">${esc(ER_STATEMENT_GUIDE.openingQuestion)}</label><span class="mini-l">${esc(ER_STATEMENT_GUIDE.responseLabel)}</span>
    <textarea id="iv-opening-${iv.id}" style="min-height:70px" oninput="syncInterviewDraft('${iv.id}')">${esc(d.opening)}</textarea>
    <div class="interview-pairs" aria-label="Case-specific questions">
      ${d.pairs.map((pair,index)=>`<div class="interview-pair" data-pair-id="${esc(pair.id)}"><label class="mini-l" for="iv-q-${iv.id}-${pair.id}">Question ${index+1}</label><textarea id="iv-q-${iv.id}-${pair.id}" oninput="syncInterviewDraft('${iv.id}')" placeholder="Question">${esc(pair.question)}</textarea><label class="mini-l" for="iv-a-${iv.id}-${pair.id}">${esc(ER_STATEMENT_GUIDE.responseLabel)}</label><textarea id="iv-a-${iv.id}-${pair.id}" oninput="syncInterviewDraft('${iv.id}')" placeholder="${esc(ER_STATEMENT_GUIDE.responseLabel.trim())}">${esc(pair.response)}</textarea><div class="file-actions"><button class="btn sm ghost" onclick="moveInterviewPair('${caseId}','${iv.id}',${index},-1)" ${index===0?'disabled':''} aria-label="Move question ${index+1} up">↑</button><button class="btn sm ghost" onclick="moveInterviewPair('${caseId}','${iv.id}',${index},1)" ${index===d.pairs.length-1?'disabled':''} aria-label="Move question ${index+1} down">↓</button><button class="btn sm ghost" onclick="removeInterviewPair('${caseId}','${iv.id}',${index})">Remove</button></div></div>`).join("")}
      <button class="btn sm ghost" onclick="addInterviewPair('${caseId}','${iv.id}')" ${d.pairs.length>=50?'disabled':''}>Add question and response</button>
    </div>
    <label class="mini-l" for="iv-closing-${iv.id}" style="margin-top:10px">${esc(ER_STATEMENT_GUIDE.closingQuestion)}</label><span class="mini-l">${esc(ER_STATEMENT_GUIDE.responseLabel)}</span>
    <textarea id="iv-closing-${iv.id}" style="min-height:70px" oninput="syncInterviewDraft('${iv.id}')">${esc(d.closing)}</textarea>
    <label class="mini-l" for="iv-notes-${iv.id}" style="margin-top:10px">Working notes (not copied into statement responses)</label>
    <textarea id="iv-notes-${iv.id}" style="min-height:90px" oninput="syncInterviewDraft('${iv.id}')" onblur="saveInterviewUI('${caseId}','${iv.id}',true)">${esc(d.notes)}</textarea>
    <div style="display:flex;gap:8px;margin-top:8px;flex-wrap:wrap"><button class="btn sm sec" onclick="saveInterviewUI('${caseId}','${iv.id}')">Save</button><button class="btn sm ghost" onclick="downloadFilledStatement('${caseId}','${iv.id}')">Download filled statement</button><button class="btn sm ghost" onclick="exportInterviewPdf('${caseId}','${iv.id}')">Export interview (PDF)</button><span class="muted" id="iv-saved-${iv.id}" style="font-size:12px;align-self:center"></span><button class="btn sm ghost" style="margin-left:auto" onclick="deleteInterviewUI('${iv.id}')">Remove</button></div>
  </div>`;
}
function syncInterviewDraft(id){
  const d=interviewDrafts.get(id); if(!d)return;
  const read=k=>$(`iv-${k}-${id}`)?.value;
  for(const [key,field] of Object.entries({interviewee:"name",role:"role",date:"date",time:"time",timezone:"zone",format:"format",duration:"duration",title:"title",location:"location",interviewer:"by",status:"status",followUp:"fu",opening:"opening",closing:"closing",notes:"notes",caNew:"ca-new"})) if(read(field)!=null)d[key]=read(field);
  d.pairs.forEach(pair=>{const q=$(`iv-q-${id}-${pair.id}`),a=$(`iv-a-${id}-${pair.id}`);if(q)pair.question=q.value;if(a)pair.response=a.value;});
}
function rerenderInterview(caseId,id){ syncInterviewDraft(id); const row=$(`iv-${id}`),iv=caseExport?.interviews?.find(item=>item.id===id); if(row&&iv){row.outerHTML=interviewEditorHtml(caseId,iv);setInterviewContactBusy(id,!!interviewDrafts.get(id)?.attemptPromise);} }
function addInterviewPair(caseId,id){syncInterviewDraft(id);const d=interviewDrafts.get(id);if(!d||d.pairs.length>=50)return;d.pairs.push({id:crypto.randomUUID(),question:"",response:""});rerenderInterview(caseId,id);}
function removeInterviewPair(caseId,id,index){syncInterviewDraft(id);const d=interviewDrafts.get(id);if(!d)return;d.pairs.splice(index,1);rerenderInterview(caseId,id);}
function moveInterviewPair(caseId,id,index,delta){syncInterviewDraft(id);const d=interviewDrafts.get(id),to=index+delta;if(!d||to<0||to>=d.pairs.length)return;[d.pairs[index],d.pairs[to]]=[d.pairs[to],d.pairs[index]];rerenderInterview(caseId,id);}
// ---- T135: contact-attempt log (saved immediately via its own RPC; needs
// migration 20260915 set_interview_contact_attempts) ------------------------
function setInterviewContactBusy(id,busy){
  const box=$(`iv-${id}`)?.querySelector(".iv-attempts");
  if(box)box.querySelectorAll("button").forEach(button=>{button.disabled=busy;});
}
async function persistInterviewContactAttempts(caseId,id){
  const d=interviewDrafts.get(id); if(!d)return false;
  const attempts=d.attempts.map(a=>({...a})), epoch=sessionEpoch;
  const current=()=>epoch===sessionEpoch && selected===caseId && interviewDrafts.get(id)===d;
  const run=(async()=>{
    let error;
    try{ ({error}=await sb.rpc("set_interview_contact_attempts",{p_id:id,p_case_id:caseId,p_attempts:attempts,p_expected_attempts:d.savedAttempts.map(a=>({...a}))})); }
    catch(caught){ error=caught; }
    if(!current())return null;
    if(error){ alert(errText(error)); return false; }
    d.savedAttempts=attempts.map(a=>({...a}));
    const row=caseExport?.interviews?.find(item=>item.id===id);
    if(row)row.contact_attempts=attempts;
    return true;
  })();
  d.attemptPromise=run; setInterviewContactBusy(id,true);
  try{return await run;}
  finally{d.attemptPromise=null;if(current())setInterviewContactBusy(id,false);}
}
async function logInterviewContactAttempt(caseId,id){
  syncInterviewDraft(id);
  const d=interviewDrafts.get(id); if(!d||d.attemptPromise)return;
  const submitted=$(`iv-ca-new-${id}`)?.value||"",note=submitted.trim();
  if(!note){ alert('Describe the contact attempt (e.g. "called 3x, no answer").'); return; }
  if(d.attempts.length>=100){ alert("This interview already has the maximum of 100 logged attempts."); return; }
  d.attempts.push({id:crypto.randomUUID(),at:new Date().toISOString(),note});
  if(await persistInterviewContactAttempts(caseId,id)){
    // Keep the next note if the handler typed while the first was saving.
    const input=$(`iv-ca-new-${id}`);
    if(input?.value===submitted){input.value="";d.caNew="";}
    rerenderInterview(caseId,id);
    const next=$(`iv-ca-new-${id}`); if(next)next.focus();
  } else d.attempts.pop();
}
async function removeInterviewContactAttempt(caseId,id,index){
  syncInterviewDraft(id);
  const d=interviewDrafts.get(id); if(!d||d.attemptPromise||!d.attempts[index])return;
  if(!confirm("Remove this contact attempt from the log?"))return;
  const removed=d.attempts.splice(index,1);
  if(await persistInterviewContactAttempts(caseId,id)) rerenderInterview(caseId,id);
  else d.attempts.splice(index,0,...removed);
}
// ---- T135: per-interview export (print dialog → Save as PDF) ---------------
function interviewExportDocHtml(iv,snapshot=caseExport){
  const dash=v=>(v==null||v==="")?"—":esc(v);
  const kv=(k,v)=>`<tr><th>${esc(k)}</th><td>${(v==null||v==="")?"—":v}</td></tr>`;
  const code=interviewCode(snapshot,iv.id)||snapshot?.c?.ref||"interview";
  return `<!doctype html><html lang="en"><head><meta charset="utf-8">
<title>${esc(code)} — interview</title>
<style>${CASE_SUMMARY_CSS}</style></head><body>
<h1>${esc(code)} <span class="pillx">Interview</span></h1>
<div class="sub">Earthbar &amp; Beaming — People Support Portal · Case ${esc(snapshot?.c?.ref||"")} · Interview record · exported ${esc(new Date().toLocaleString())}</div>
${interviewSummaryHtml(iv,kv,dash,snapshot)}
</body></html>`;
}
async function exportInterviewPdf(caseId,id){
  const button=document.activeElement; if(button instanceof HTMLButtonElement)button.disabled=true;
  try{
    const contactSave=interviewDrafts.get(id)?.attemptPromise;
    if(contactSave && !await contactSave)return;
    if(!await saveInterviewUI(caseId,id,false))return;
    const iv=caseExport?.interviews?.find(item=>item.id===id); if(!iv)return;
    const win=window.open("","_blank");
    if(!win){ alert("Allow pop-ups for this site to export the interview as a PDF."); return; }
    win.document.open(); win.document.write(interviewExportDocHtml(iv,caseExport)); win.document.close();
    setTimeout(()=>{ try{ win.focus(); win.print(); }catch{} },250);
  }finally{ if(button instanceof HTMLButtonElement&&button.isConnected)button.disabled=false; }
}
function interviewPayload(caseId,id){
  syncInterviewDraft(id);const d=interviewDrafts.get(id); if(!d)return null;
  const duration=d.duration===""?null:Number(d.duration);
  return {p_id:id,p_case_id:caseId,p_interviewee:d.interviewee,p_role:d.role||null,p_date:d.date||null,p_local_time:d.time||null,p_timezone:d.time?(d.timezone||null):null,p_format:d.format||null,p_duration_minutes:duration,p_interviewee_title:d.title||null,p_interviewee_location:d.location||null,p_interviewer:d.interviewer||null,p_status:d.status,p_notes:d.notes||null,p_follow_up:d.followUp||null,p_question_responses:d.pairs.map(pair=>({...pair})),p_opening_response:d.opening||null,p_closing_response:d.closing||null};
}
// Explicit Save and notes-blur autosave share one per-interview queue. The DOM is
// never repainted after a save, so a failed or older request cannot erase typing.
function saveInterviewUI(caseId, id, silent){
  const payload=interviewPayload(caseId,id); if(!payload)return Promise.resolve(false);
  const key = `${caseId}:${id}`;
  const previous = interviewSavePromises.get(key);
  const run = (async()=>{
    if(previous) await previous;
    let error;
    try { ({error} = await sb.rpc("save_interview_v2", payload)); }
    catch(caught) { error = caught; }
    const s = $(`iv-saved-${id}`);
    if(error){ if(s) s.textContent = "Save failed"; if(!silent) alert(errText(error)); return false; }
    if(s) s.textContent = "Saved " + new Date().toLocaleTimeString();
    const row=caseExport?.interviews?.find(item=>item.id===id);
    if(row)Object.assign(row,{interviewee:payload.p_interviewee,role_in_case:payload.p_role,interview_date:payload.p_date,interview_local_time:payload.p_local_time,interview_timezone:payload.p_timezone,interview_format:payload.p_format,duration_minutes:payload.p_duration_minutes,interviewee_title:payload.p_interviewee_title,interviewee_location:payload.p_interviewee_location,interviewer:payload.p_interviewer,status:payload.p_status,notes:payload.p_notes,follow_up:payload.p_follow_up,question_responses:payload.p_question_responses,opening_response:payload.p_opening_response,closing_response:payload.p_closing_response});
    return true;
  })();
  let tracked;
  tracked = run.finally(()=>{ if(interviewSavePromises.get(key) === tracked) interviewSavePromises.delete(key); });
  interviewSavePromises.set(key,tracked);
  return tracked;
}
async function addInterviewUI(caseId){
  const name = ($("ni-name")?.value || "").trim();
  if(!name){ alert("Enter the name of the person interviewed."); return; }
  const time=$("ni-time")?.value||null;
  const { error } = await sb.rpc("save_interview_v2", {
    p_id: null, p_case_id: caseId, p_interviewee: name,
    p_role: $("ni-role")?.value ?? null, p_date: $("ni-date")?.value || null,
    p_local_time:time,p_timezone:time?($("ni-zone")?.value||null):null,p_format:$("ni-format")?.value||null,
    p_duration_minutes:$("ni-duration")?.value?Number($("ni-duration").value):null,p_interviewee_title:$("ni-title")?.value||null,
    p_interviewee_location:$("ni-location")?.value||null,p_interviewer:$("ni-by")?.value||null,p_status:"Scheduled",
    p_notes:null,p_follow_up:null,p_question_responses:[],p_opening_response:null,p_closing_response:null });
  if(error){ alert(errText(error)); return; }
  render();
}
async function deleteInterviewUI(id){
  if(!confirm("Remove this interview (including its notes)?")) return;
  const { error } = await sb.rpc("delete_interview", { p_id: id });
  if(error){ alert(errText(error)); return; }
  interviewDrafts.delete(id);
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
  const guide=ER_STATEMENT_GUIDE;
  return `<div class="guide" id="er-statement-guide">
    <div class="g-sec"><span class="mini-l">Statement details</span><ul>${guide.metadataLabels.map(label=>`<li>${esc(label)}</li>`).join("")}</ul></div>
    <div class="g-sec"><span class="mini-l">Interview script</span>${guide.script.map(line=>`<p>${esc(line)}</p>`).join("")}</div>
    <div class="g-sec"><span class="mini-l">Opening question</span><p>${esc(guide.openingQuestion)}</p></div>
    <div class="g-sec"><span class="mini-l">Source question placeholders</span><ul>${guide.variableQuestionPlaceholders.map(q=>`<li>${esc(q)}</li>`).join("")}</ul><p>${esc(guide.responseLabel)}</p></div>
    <div class="g-sec"><span class="mini-l">Closing question</span><p>${esc(guide.closingQuestion)}</p></div>
  </div>`;
}
function implicatedPeopleForStatement(snapshot=caseExport){
  return (snapshot?.parties||[]).filter(p=>p.role_in_case==="subject").map(p=>p.party_type==="customer"||(!p.subject_id&&p.display_name)?(p.display_name||"Customer"):nameOf(p.subject_id)).filter(Boolean).join("; ");
}
function statementModel(iv,snapshot=caseExport){
  const pairs=interviewPairs(iv.question_responses);
  return {metadata:{interviewer:iv.interviewer||"",date:iv.interview_date||"",time:iv.interview_local_time?fmtLocalTime(iv.interview_local_time,iv.interview_timezone):"",interviewee:iv.interviewee||"",intervieweeTitle:iv.interviewee_title||"",intervieweeLocation:iv.interviewee_location||"",duration:iv.duration_minutes?`${iv.duration_minutes} minutes`:"",format:iv.interview_format||"",caseReference:snapshot?.c?.ref||"",implicatedPerson:implicatedPeopleForStatement(snapshot)},openingResponse:iv.opening_response||"",pairs,closingResponse:iv.closing_response||""};
}
async function ensureStatementTemplate(){
  if(!statementTemplatePromise){const epoch=sessionEpoch,userId=session?.user?.id;statementTemplatePromise=(async()=>{const current=()=>epoch===sessionEpoch&&session?.user?.id===userId;if(!current())throw Object.assign(new Error("Statement download cancelled."),{cancelled:true});const {data,error}=await sb.storage.from(STATEMENT_TEMPLATE_BUCKET).download(STATEMENT_TEMPLATE_OBJECT);if(!current()){clearStatementTemplate();throw Object.assign(new Error("Statement download cancelled."),{cancelled:true});}if(error)throw error;await configureStatementTemplate(data);if(!current()){clearStatementTemplate();throw Object.assign(new Error("Statement download cancelled."),{cancelled:true});}})().catch(error=>{statementTemplatePromise=null;throw error;});}
  return statementTemplatePromise;
}
async function downloadBlankStatement(){try{await ensureStatementTemplate();downloadBlob(buildBlankBlob(),STATEMENT_TEMPLATE_FILENAME);}catch(error){if(!error.cancelled)alert(`The approved statement could not be downloaded. ${errText(error)}`);}}
async function downloadFilledStatement(caseId,id){
  const button=document.activeElement; if(button instanceof HTMLButtonElement)button.disabled=true;
  try{
    if(!await saveInterviewUI(caseId,id,false))return;
    await ensureStatementTemplate();
    const iv=caseExport?.interviews?.find(item=>item.id===id);if(!iv)return;
    const leaf=String(iv.interviewee||"interview").replace(/[^A-Za-z0-9 _.-]/g,"_").trim()||"interview";
    downloadBlob(buildFilledBlob(statementModel(iv)),`${leaf} - filled ER statement.docx`);
  }catch(error){if(!error.cancelled)alert(`The filled statement could not be downloaded. ${errText(error)}`);}finally{if(button instanceof HTMLButtonElement&&button.isConnected)button.disabled=false;}
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
  const epoch=sessionEpoch, userId=session?.user?.id;
  const current = caseExport?.c?.id===id ? caseExport.c : dashboardData.find(c=>c.id===id);
  const wasClosed = current?.state === "Closed";
  const {error}=await sb.rpc("advance_state",{p_case_id:id,p_to:to});
  if(epoch!==sessionEpoch || session?.user?.id!==userId || selected!==id) return;
  if(error){ alert(errText(error)); render(); return; }
  if(wasClosed && dashView==="closed"){
    selected=null;
    dashView=current?.intake_type==="request" ? "requests" : "cases";
    filters=blankDashboardFilters();
  }
  render();
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
  const results = !lookup.picked ? employeeMatches(lookup.query) : [];   // shared accent-insensitive lookup (T136)
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
    ${employeeTestBanner()}
    <h2 class="section">Check the status of your report</h2>
    <p class="muted">Reported anonymously? Enter your claim code. You'll also get email updates automatically whenever your case changes.</p>
    <label>Claim code</label>
    <div style="display:flex;gap:8px"><input id="cc" type="text" placeholder="e.g. ACDE-4679" value="${esc(statusResult?.tried||'')}"><button class="btn" onclick="doStatusCheck()">Check</button></div>
    ${statusResult ? (statusResult.error ? `<div class="banner err">${esc(statusResult.error)}</div>` : statusResult.found ? renderStatusCard(statusResult) : `<div class="banner warn">No report found for that code.</div>`) : ""}
  </div>
  <div class="card">
    <b style="font-size:14px">Reports you submitted with your name</b>
    ${myReportsLoading?'<p class="muted">Loading your reports…</p>':myReportsError?`<div class="banner err">${esc(myReportsError)} <button class="btn sm sec" onclick="retryMyReports()">Retry</button></div>`:myReports.length?`<table style="margin-top:10px"><thead><tr><th>Ref</th><th>Category</th><th>Status</th><th>Submitted</th><th></th></tr></thead>
      <tbody>${myReports.map(c=>`<tr><td><span class="ref">${esc(c.ref)}</span></td><td>${esc(c.category)}</td><td>${pill(c.state)}</td><td>${fmt(c.created_at)}</td><td><button class="btn sm sec" data-ref="${esc(c.ref)}" onclick="openNamedReportMessages(this.dataset.ref)">Messages</button></td></tr>`).join("")}</tbody></table>`
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
  closeAttachmentPreview(false);
  const code = $("cc")?.value.trim().toUpperCase(); if(!code) return;
  const epoch = sessionEpoch, generation = ++statusLookupGeneration;
  messageThreadGeneration += 1;
  const current=()=>epoch===sessionEpoch && generation===statusLookupGeneration && view==="status";
  let data, error;
  try{ ({data,error}=await sb.rpc("check_status",{p_claim_code:code})); }
  catch(e){ error=e; }
  if(!current()) return;
  statusResult = error
    ? {tried:code,found:false,error:"Status lookup is temporarily unavailable. Please try again."}
    : Object.assign({tried:code}, data);
  if(!error&&statusResult.found) await loadMessageThread(null,code,null);
  if(current()) render();
}
async function openNamedReportMessages(caseRef){
  closeAttachmentPreview(false);if(!caseRef)return;statusResult={tried:"",found:true,ref:caseRef,state:"",handler:"",named:true};
  await loadMessageThread(null,null,caseRef);render();
  $("message-body")?.focus();
}
function renderStatusCard(s){
  return `<div class="divider"></div>
    <div class="kv"><span class="k">Reference</span><span class="ref">${esc(s.ref)}</span></div>
    <div class="kv"><span class="k">Status</span>${pill(s.state)}</div>
    <div class="kv"><span class="k">Handled by</span><span>${esc(s.handler||'—')}</span></div>
    <b style="font-size:13px;display:block;margin-top:14px">Messages with HR</b>
    ${messageThreadHtml(null,s.named?null:s.tried,false,s.named?s.ref:null)}`;
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
  const header = [...cols, "district_leader"];
  const rows = lastShown.map(c => [...cols.map(k => csvCell(c[k])), csvCell(districtLeaderLabel(caseDistrictLeader(c)))].join(","));
  // BOM so Excel detects UTF-8; CRLF line endings for the same reason
  const csv = "\uFEFF" + [header.join(","), ...rows].join("\r\n") + "\r\n";
  downloadBlob(new Blob([csv], {type:"text/csv;charset=utf-8"}), `hr-cases-${todayStr()}.csv`);
}
// ---- case .zip export: printable summary + message thread + raw JSON --------
function caseMessagesTxt(snapshot=caseExport){
  const { c, messages, handlerName } = snapshot;
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
function interviewSummaryHtml(iv,kv,dash,snapshot=caseExport){
  const pairs=interviewPairs(iv.question_responses);
  const attempts=interviewAttempts(iv.contact_attempts);
  const localTime=iv.interview_local_time?esc(fmtLocalTime(iv.interview_local_time,iv.interview_timezone)):"Time not recorded";
  const code=interviewCode(snapshot,iv.id);
  return `<article class="interview-summary"><table class="kv" style="margin-bottom:10px">
    ${code?kv("Interview reference",esc(code)):""}
    ${kv("Interviewee",dash(iv.interviewee)+(iv.role_in_case?` (${esc(rlabel(iv.role_in_case))})`:""))}
    ${kv("Date",iv.interview_date?esc(fmtDateOnly(iv.interview_date)):"—")}${kv("Local time / IANA zone",localTime)}
    ${kv("Format",dash(iv.interview_format))}${kv("Duration",iv.duration_minutes?`${esc(iv.duration_minutes)} minutes`:"—")}
    ${kv("Interviewee title",dash(iv.interviewee_title))}${kv("Interviewee location",dash(iv.interviewee_location))}
    ${kv("Interviewer / status",dash(iv.interviewer)+" · "+dash(iv.status))}${iv.follow_up?kv("Follow-up",esc(iv.follow_up)):""}
  </table>
  ${attempts.length?`<h3>Contact attempts</h3><table class="grid"><tr><th>When</th><th>Attempt</th></tr>${attempts.map(a=>`<tr><td style="white-space:nowrap">${esc(fmt(a.at)||"—")}</td><td>${esc(a.note)}</td></tr>`).join("")}</table>`:""}
  <h3>Interview introduction (read to the interviewee)</h3><div class="box">${ER_STATEMENT_GUIDE.script.map(line=>esc(line)).join("\n")}</div>
  <h3>${esc(ER_STATEMENT_GUIDE.openingQuestion)}</h3><div><b>${esc(ER_STATEMENT_GUIDE.responseLabel)}</b></div><div class="box">${esc(iv.opening_response||"")}</div>
  ${pairs.map((pair,index)=>`<h3>Question ${index+1}: ${esc(pair.question)}</h3><div><b>${esc(ER_STATEMENT_GUIDE.responseLabel)}</b></div><div class="box">${esc(pair.response)}</div>`).join("")}
  <h3>${esc(ER_STATEMENT_GUIDE.closingQuestion)}</h3><div><b>${esc(ER_STATEMENT_GUIDE.responseLabel)}</b></div><div class="box">${esc(iv.closing_response||"")}</div>
  ${iv.notes?`<h3>Working notes (separate from statement responses)</h3><div class="box" style="margin-bottom:16px">${esc(iv.notes)}</div>`:""}</article>`;
}
// Shared print stylesheet for the case summary and per-interview export docs.
const CASE_SUMMARY_CSS = `
  body{font-family:"Helvetica Neue",Helvetica,Arial,sans-serif;color:#111;margin:32px auto;max-width:820px;line-height:1.5;font-size:14px}
  h1{font-size:22px;margin:0 0 2px} .sub{color:#6b6b6b;font-size:12px;margin-bottom:20px}
  h2{font-size:13px;text-transform:uppercase;letter-spacing:.1em;border-bottom:1px solid #111;padding-bottom:4px;margin:26px 0 10px}
  table{border-collapse:collapse;width:100%} th,td{text-align:left;padding:5px 10px;vertical-align:top;border-bottom:1px solid #eee;font-size:13.5px}
  table.kv th{width:190px;color:#6b6b6b;font-weight:600;font-size:11px;text-transform:uppercase;letter-spacing:.07em}
  table.grid th{color:#6b6b6b;font-size:11px;text-transform:uppercase;letter-spacing:.07em}
  .box{border:1px solid #ddd;background:#fafafa;padding:12px 14px;white-space:pre-wrap}
  .muted{color:#6b6b6b} .pillx{display:inline-block;border:1px solid #111;padding:1px 8px;font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.06em}
  @media print{body{margin:12px}}
`;
function caseSummaryHtml(snapshot=caseExport){
  const { c, parties, events, tasks, messages, notes, allegations, interviews, actions, attachments=[], handlerName } = snapshot;
  const isReq = c.intake_type === "request";
  const dash = v => (v==null || v==="") ? "—" : esc(v);
  const kv = (k, v) => `<tr><th>${esc(k)}</th><td>${(v==null||v==="")?"—":v}</td></tr>`;
  const sec = (t, body) => `<section><h2>${esc(t)}</h2>${body}</section>`;
  const partyLine = p => p.party_type==="customer" || (!p.subject_id && p.display_name)
    ? `${esc(p.display_name||"Customer")} (customer, ${esc(rlabel(p.role_in_case))})`
    : `${esc(nameOf(p.subject_id))} (${esc(roleOf(p.subject_id)||"")}${p.role_in_case?", "+esc(rlabel(p.role_in_case)):""})`;
  return `<!doctype html><html lang="en"><head><meta charset="utf-8">
<title>${esc(c.ref)} — case summary</title>
<style>${CASE_SUMMARY_CSS}</style></head><body>
<h1>${esc(c.ref)} <span class="pillx">${esc(stlabel(c.state))}</span></h1>
<div class="sub">Earthbar &amp; Beaming — People Support Portal · ${isReq?'Request':'Incident case'} summary · exported ${esc(new Date().toLocaleString())}</div>
${sec("Overview", `<table class="kv">
  ${kv("Category", dash(c.category))}
  ${kv("Status", esc(stlabel(c.state)))}
  ${kv("Closure categorization", c.closure_category ? esc(c.closure_category)+(c.closure_ref?` — duplicate of ${esc(c.closure_ref)}`:"") : "—")}
  ${isReq?"":kv(L(c,'riskCol'), dash(caseRisk(c)))}
  ${kv("Location", dash(c.location)+(c.us_state?`, ${esc(c.us_state)}`:""))}
  ${kv("District leader", esc(districtLeaderLabel(caseDistrictLeader(c))))}
  ${kv("Opened", esc(fmtD(c.created_at)))}
  ${isReq?"":kv("Occurred", c.incident_date?esc(fmtDateOnly(c.incident_date)):"—")}
  ${kv("Closed", c.closed_at?esc(fmtD(c.closed_at)):"—")}
  ${kv(L(c,'reporter'), c.anonymous?"Anonymous":dash(requesterLine(c)))}
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
  ? interviews.map(iv=>interviewSummaryHtml(iv,kv,dash,snapshot)).join("")
  : `<p class="muted">None recorded.</p>`) }
${sec("Follow-up tasks", tasks.length
  ? `<table class="grid"><tr><th>Task</th><th>Status</th><th>Due</th></tr>${tasks.map(t=>`<tr><td>${dash(t.title)}</td><td>${dash(t.status)}</td><td>${t.due_at?esc(fmt(t.due_at)):"—"}</td></tr>`).join("")}</table>`
  : `<p class="muted">No tasks.</p>`)}
${sec("HR notes", notes.length
  ? notes.map(n=>`<div class="box" style="margin-bottom:10px"><div class="muted" style="font-size:11px">${esc(n.author_email||"")} · ${esc(fmt(n.created_at))}</div>${esc(n.body)}</div>`).join("")
  : `<p class="muted">No notes.</p>`)}
${sec("Attachments included in this export", attachments.length
  ? `<table class="grid"><tr><th>File</th><th>Size</th><th>Source</th></tr>${attachments.map(f=>`<tr><td>${esc(f.file_name)}</td><td>${esc(fmtBytes(f.size_bytes))}</td><td>${esc(f.source)}</td></tr>`).join("")}</table>`
  : `<p class="muted">No attachments.</p>`)}
${sec("Timeline (audit log)", events.length
  ? `<table class="grid"><tr><th>When</th><th>Type</th><th>Note</th></tr>${events.map(e=>`<tr><td style="white-space:nowrap">${esc(fmt(e.at))}</td><td>${dash(e.type)}</td><td>${dash(e.note)}</td></tr>`).join("")}</table>`
  : `<p class="muted">No events.</p>`)}
${sec("Messages", `<p class="muted">${messages.length} message(s) — full thread in <b>messages.txt</b> in this export.</p>`)}
</body></html>`;
}
const MAX_CASE_EXPORT_BYTES = 100 * 1024 * 1024;
const MAX_CASE_EXPORT_ATTACHMENTS = 5000;
const CASE_EXPORT_PAGE_SIZE = 100;
const portalEvidenceDisplayName = name => String(name || "attachment")
  .replace(/^(?:\d{10,}|[0-9a-f]{8}-[0-9a-f-]{27})_/i, "");
function safeZipFileName(value){
  let leaf = String(value || "attachment").split(/[\\/]/).pop()
    .replace(/[<>:"|?*\x00-\x1f\x7f\u0085\u200b-\u200f\u2028-\u202e\u2066-\u2069]/g, "_").trim().replace(/[. ]+$/g, "");
  if(!leaf || /^\.+$/.test(leaf)) return "attachment";
  if(leaf.length > 180){
    const dot = leaf.lastIndexOf(".");
    const extension = dot > 0 && leaf.length - dot <= 16 ? leaf.slice(dot) : "";
    const stem = extension ? leaf.slice(0,dot) : leaf;
    leaf = stem.slice(0,180-extension.length).replace(/[. ]+$/g, "") + extension;
  }
  leaf = leaf.replace(/[. ]+$/g, "");
  if(!leaf || /^\.+$/.test(leaf)) return "attachment";
  if(/^(?:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)/i.test(leaf)) leaf = `_${leaf}`;
  return leaf;
}
function uniqueZipPath(folder, fileName, used){
  const safe = safeZipFileName(fileName);
  const dot = safe.lastIndexOf(".");
  const stem = dot > 0 ? safe.slice(0, dot) : safe;
  const ext = dot > 0 ? safe.slice(dot) : "";
  let candidate = `${folder}/${safe}`, suffix = 2;
  while(used.has(candidate.toLowerCase())) candidate = `${folder}/${stem} (${suffix++})${ext}`;
  used.add(candidate.toLowerCase());
  return candidate;
}
async function listAllCaseEvidence(caseId){
  const files = [];
  for(let offset=0;;offset+=100){
    const { data, error } = await sb.storage.from("evidence").list(caseId, {
      limit:100, offset, sortBy:{column:"name",order:"asc"},
    });
    if(error) throw new Error("The portal evidence list could not be loaded.");
    const batch = data || [];
    files.push(...batch.filter(item=>item && item.id !== null));
    if(batch.length < 100) break;
  }
  return files;
}
async function assertFreshCaseExportAccess(caseId){
  const {data, error} = await sb.from("cases").select("id,updated_at").eq("id",caseId).maybeSingle();
  if(error || !data) throw new Error("Case access could not be confirmed. Refresh the case and try again.");
  return data;
}
async function fetchAllCaseExportRows(table, caseId, orderColumn){
  const rows = [];
  for(let from=0;;from+=CASE_EXPORT_PAGE_SIZE){
    let query = sb.from(table).select("*").eq("case_id",caseId).order(orderColumn,{ascending:true});
    if(orderColumn !== "id") query = query.order("id",{ascending:true});
    const {data, error} = await query.range(from, from + CASE_EXPORT_PAGE_SIZE - 1);
    if(error) throw new Error(`A complete export cannot be created because ${table.replaceAll("_"," ")} did not load. Refresh the case and try again.`);
    const batch = data || [];
    rows.push(...batch);
    if(batch.length < CASE_EXPORT_PAGE_SIZE) break;
  }
  return rows;
}
async function loadFreshCaseExportSnapshot(source, caseId){
  const {data:c, error} = await sb.from("cases").select(CASE_DETAIL_COLS).eq("id",caseId).maybeSingle();
  if(error || !c) throw new Error("Case access could not be confirmed. Refresh the case and try again.");
  const specs = [
    ["parties", "case_parties", "id"], ["events", "case_events", "at"],
    ["tasks", "tasks", "created_at"], ["messages", "messages", "created_at"],
    ["notes", "case_notes", "created_at"], ["allegations", "case_allegations", "created_at"],
    ["interviews", "case_interviews", "created_at"], ["actions", "corrective_actions", "created_at"],
    ["files", "case_files", "created_at"],
  ];
  const results = await Promise.all(specs.map(([,table,order])=>fetchAllCaseExportRows(table,caseId,order)));
  const snapshot = {...source, c:{...c}, exportLoadErrors:[], handlerName:c.external?"External advisor":nameOf(c.handler_id)};
  specs.forEach(([key], index)=>{ snapshot[key] = results[index]; });
  return snapshot;
}
function caseFilePathAllowed(file, caseId){
  const parts = String(file.storage_path||"").split("/");
  if(parts.length < 2 || parts.some(part=>!part || part === "." || part === "..")) return false;
  if(file.source === "email") return parts[0] === `case_${caseId}`;
  return parts[0] === `case_${caseId}` || parts[0] === caseId;
}
const portalInventorySignature = files => files.map(file=>[
  file.id||"", file.name||"", Number(file.metadata?.size)||0,
].join("\u0000")).sort().join("\u0001");
const caseFileInventorySignature = files => files.map(file=>[
  file.id||"", file.storage_path||"", file.file_name||"", file.source||"", Number(file.size_bytes)||0,
].join("\u0000")).sort().join("\u0001");
async function awaitPendingInterviewSaves(caseId, button){
  if(document.activeElement?.id?.startsWith("iv-")) document.activeElement.blur();
  await Promise.resolve();
  const pending = (caseExport?.interviews||[]).map(async iv=>{
    const contactSave=interviewDrafts.get(iv.id)?.attemptPromise;
    if(contactSave && !await contactSave)return false;
    return saveInterviewUI(caseId,iv.id,true);
  });
  if(!pending.length) return;
  const status = $("case-export-status");
  if(status?.isConnected) status.textContent = "Saving interviews…";
  const results = await Promise.all(pending);
  if(results.some(saved=>!saved)) throw new Error("Interview details could not be saved, so the export was stopped. Save them and retry.");
}
function attachmentManifest(snapshot){
  const lines = [
    `Attachment manifest — ${snapshot.c.ref}`,
    `Exported ${snapshot.exported_at}`,
    "All attachments listed below are included in this archive.",
    "Reference suffixes (a, b, … z, aa, ab, …) number this case's interviews and attachments in the order they were filed at the time of export.",
    "=".repeat(64), "",
  ];
  if(!snapshot.attachments.length) lines.push("(no attachments)");
  snapshot.attachments.forEach((file, i)=>lines.push(
    `${i+1}. ${file.file_name}`,
    ...(file.export_code?[`   Reference: ${file.export_code}`]:[]),
    `   Source: ${file.source}`,
    `   Archive path: ${file.zip_path}`,
    `   Size: ${file.size_bytes} bytes`, "",
  ));
  const interviewRefs=(snapshot.interviews||[]).map((iv,i)=>`${interviewCode(snapshot,iv.id)} — interview: ${iv.interviewee||"(unnamed)"}`);
  if(interviewRefs.length) lines.push("Interview references (documents in the interviews/ folder):", ...interviewRefs.map(r=>`  ${r}`), "");
  return lines.join("\r\n");
}
function assertCaseZipBudget(files, maxBytes=MAX_CASE_EXPORT_BYTES){
  const encoder = new TextEncoder();
  const payloadBytes = files.reduce((total,file)=>total + (typeof file.data === "string"
    ? encoder.encode(file.data).byteLength : file.data.byteLength), 0);
  const headerBytes = 22 + files.reduce((total,file)=>total + 76 + 2*encoder.encode(file.name).byteLength, 0);
  if(payloadBytes + headerBytes > maxBytes){
    throw new Error("This case export is larger than 100 MB. Export attachments separately or contact support for a larger archive.");
  }
}
async function exportCaseZip(){
  if(!caseExport || !selected || caseExport.c?.id !== selected){ alert("Open a case first."); return; }
  if(caseExportInProgress) return;
  caseExportInProgress = true;
  const exportGeneration = ++caseExportGeneration;
  const source = caseExport;
  const caseId = source.c.id, epoch = sessionEpoch, userId = session?.user?.id;
  const sourceUpdatedAt = source.c.updated_at;
  const button = $("case-export-btn");
  const status = $("case-export-status");
  if(button){ button.disabled = true; button.setAttribute("aria-busy","true"); }
  if(status) status.textContent = "Preparing export…";
  const stillCurrent = () => epoch === sessionEpoch && session?.user?.id === userId
    && selected === caseId && caseExport === source && source.c.updated_at === sourceUpdatedAt
    && caseExportGeneration === exportGeneration;
  try {
    await awaitPendingInterviewSaves(caseId,button);
    if(!stillCurrent()) throw new Error("Export cancelled because the open case or session changed.");
    const fresh = await loadFreshCaseExportSnapshot(source, caseId);
    if(!stillCurrent()) throw new Error("Export cancelled because the open case or session changed.");
    const messageListResult=await messageAttachmentAction({action:"list",mode:"handler",caseId});
    if(!stillCurrent()) throw new Error("Export cancelled because the open case or session changed.");
    if(messageListResult.error) throw new Error("A complete export cannot be created because message attachments could not be authorized.");
    const messageAttachmentFiles=(messageListResult.data?.messages||[]).flatMap(message=>(message.attachments||[]).map(file=>({
      source:"Message attachment",fileName:safeZipFileName(file.name),sizeBytes:Number(file.size)||null,
      attachmentId:file.id,messageId:message.id,folder:"attachments/messages",
    })));
    const portalFiles = await listAllCaseEvidence(caseId);
    if(!stillCurrent()) throw new Error("Export cancelled because the open case or session changed.");
    const unavailable = (fresh.files||[]).filter(file=>!file.storage_path);
    if(unavailable.length){
      const names = unavailable.map(file=>safeZipFileName(file.file_name||"unnamed attachment")).join(", ");
      throw new Error(`A complete export cannot be created because these email attachments are only in the People Support mailbox: ${names}. Open each file from the mailbox, then upload it under Evidence in this case and retry.`);
    }
    const invalidPaths = (fresh.files||[]).filter(file=>!caseFilePathAllowed(file,caseId));
    if(invalidPaths.length) throw new Error("A complete export cannot be created because an attachment is not linked to this case. Contact support before exporting.");
    const candidates = [
      ...portalFiles.map(file=>({
        source:"Portal evidence", fileName:safeZipFileName(portalEvidenceDisplayName(file.name)),
        storagePath:`${caseId}/${file.name}`, sizeBytes:Number(file.metadata?.size)||null,
        folder:"attachments/portal",
      })),
      ...(fresh.files||[]).map(file=>({
        source:file.source === "email" ? "Email attachment" : `${safeZipFileName(file.source||"Case file")} attachment`,
        fileName:safeZipFileName(file.file_name||file.storage_path.split("/").pop()),
        storagePath:file.storage_path, sizeBytes:Number(file.size_bytes)||null,
        folder:file.source === "email" ? "attachments/email" : "attachments/case-files",
      })),
      ...messageAttachmentFiles,
    ];
    const seenStoragePaths = new Set(), expected = candidates.filter(file=>{
      const identity=file.attachmentId?`message:${file.attachmentId}`:`storage:${file.storagePath}`;
      if(seenStoragePaths.has(identity)) return false;
      seenStoragePaths.add(identity); return true;
    });
    if(expected.length > MAX_CASE_EXPORT_ATTACHMENTS){
      throw new Error(`This case has more than ${MAX_CASE_EXPORT_ATTACHMENTS.toLocaleString()} attachments. Contact support for an archival export.`);
    }
    const knownTotalBytes = expected.reduce((total, file)=>total + (file.sizeBytes || 0), 0);
    if(knownTotalBytes > MAX_CASE_EXPORT_BYTES) throw new Error("This case has more than 100 MB of attachments. Export them separately or contact support for a larger archive.");
    const used = new Set(["summary.html","messages.txt","case.json","attachments/manifest.txt"]);
    const zipAttachments = [], attachmentMetadata = [];
    // T135: every interview and attachment gets a suffixed case reference
    // (EB-2026-0143a, EB-2026-0143b, …) — interviews first, then attachments.
    const interviewCount = (fresh.interviews||[]).length;
    const exportCodeFor = index => `${fresh.c.ref||"case"}${exportSuffix(index)}`;
    let totalBytes = 0;
    for(const [index,file] of expected.entries()){
      if(status?.isConnected) status.textContent = `Adding attachments ${index+1}/${expected.length}…`;
      const exportCode = exportCodeFor(interviewCount + index);
      let data,error;
      if(file.attachmentId){
        const authorized=await authorizeMessageAttachment(caseId,null,file.attachmentId,null);
        if(!authorized.url){error=authorized.error||new Error("authorization failed");}
        else try {const response=await fetch(authorized.url,{credentials:"omit",referrerPolicy:"no-referrer"});if(!response.ok)throw new Error("download failed");data=await response.blob();}catch(downloadError){error=downloadError;}
      }else ({data,error}=await sb.storage.from("evidence").download(file.storagePath));
      if(!stillCurrent()) throw new Error("Export cancelled because the open case or session changed.");
      if(error || !data) throw new Error(`A complete export cannot be created because “${file.fileName}” could not be retrieved.`);
      const bytes = new Uint8Array(await data.arrayBuffer());
      if(!stillCurrent()) throw new Error("Export cancelled because the open case or session changed.");
      totalBytes += bytes.byteLength;
      if(totalBytes > MAX_CASE_EXPORT_BYTES) throw new Error("This case has more than 100 MB of attachments. Export them separately or contact support for a larger archive.");
      const zipPath = uniqueZipPath(file.folder, `${exportCode} - ${file.fileName}`, used);
      zipAttachments.push({name:zipPath,data:bytes});
      attachmentMetadata.push({
        file_name:file.fileName, source:file.source, storage_path:file.storagePath||null,
        message_id:file.messageId||null, message_attachment_id:file.attachmentId||null,
        zip_path:zipPath, size_bytes:bytes.byteLength, export_code:exportCode,
      });
    }
    if(status?.isConnected) status.textContent = "Verifying attachments…";
    const [finalPortalFiles, finalCaseFiles, finalMessageList] = await Promise.all([
      listAllCaseEvidence(caseId), fetchAllCaseExportRows("case_files",caseId,"created_at"),
      messageAttachmentAction({action:"list",mode:"handler",caseId}),
    ]);
    if(!stillCurrent()) throw new Error("Export cancelled because the open case or session changed.");
    if(portalInventorySignature(finalPortalFiles) !== portalInventorySignature(portalFiles)
      || caseFileInventorySignature(finalCaseFiles) !== caseFileInventorySignature(fresh.files||[])){
      throw new Error("Attachments changed while the export was being prepared. Retry to capture the latest files.");
    }
    if(finalMessageList.error) throw new Error("A complete export cannot be created because message attachments could not be reauthorized.");
    const messageSignature=list=>(list||[]).flatMap(m=>(m.attachments||[]).map(f=>[m.id,f.id,f.name,f.type,Number(f.size)||0].join("|")).sort()).join("\n");
    if(messageSignature(finalMessageList.data?.messages)!==messageSignature(messageListResult.data?.messages)) throw new Error("Message attachments changed while the export was being prepared. Retry to capture the latest files.");
    const finalAccess = await assertFreshCaseExportAccess(caseId);
    if(!stillCurrent()) throw new Error("Export cancelled because the open case or session changed.");
    if(finalAccess.updated_at !== fresh.c.updated_at) throw new Error("The case changed while the export was being prepared. Retry to capture the latest record.");
    const snapshot = {
      ...fresh, files:(fresh.files||[]).map(file=>({...file})),
      attachments:attachmentMetadata, exported_at:new Date().toISOString(),
      export_attachment_bytes:totalBytes,
    };
    // T135: each interview also ships as its own printable document, named by
    // its suffixed reference (open in a browser → print → Save as PDF).
    const interviewZipFiles = (snapshot.interviews||[]).map(iv=>({
      name:uniqueZipPath("interviews", `${interviewCode(snapshot,iv.id)} - ${safeZipFileName(iv.interviewee||"interview")}.html`, used),
      data:interviewExportDocHtml(iv,snapshot),
    }));
    const zipFiles = [
      { name:"summary.html", data:caseSummaryHtml(snapshot) },
      { name:"messages.txt", data:caseMessagesTxt(snapshot) },
      { name:"case.json", data:JSON.stringify(snapshot, null, 2) },
      { name:"attachments/manifest.txt", data:attachmentManifest(snapshot) },
      ...interviewZipFiles,
      ...zipAttachments,
    ];
    assertCaseZipBudget(zipFiles);
    const zip = makeZip(zipFiles);
    const safe = (fresh.c.ref || "case").replace(/[^\w.-]+/g, "-");
    downloadBlob(new Blob([zip], {type:"application/zip"}), `${safe}.zip`);
  } catch(error) {
    if(stillCurrent()) alert(error?.message || "The case export could not be created. Please try again.");
  } finally {
    if(caseExportGeneration === exportGeneration){
      caseExportInProgress = false;
      if(button?.isConnected){ button.disabled = false; button.setAttribute("aria-busy","false"); }
      if(status?.isConnected) status.textContent = "";
    }
  }
}

function medicalInviteHtml(){
  if(medicalInvite.status==="loading"||!medicalInvite.status)return `<div class="card login-card medical-return"><div class="medical-head"><div><div class="mini-l">Secure document return</div><h2 class="section">Checking your invitation</h2></div><span class="spin"></span></div><p>Confirming this request for your signed-in email…</p></div>`;
  if(medicalInvite.status==="error"){
    const code=medicalInvite.error?.code||"";
    const copy=code==="INVITE_EXPIRED"?"This secure request has expired. Contact People Support for a new invitation."
      :code==="NOT_FOUND"?"This secure request is no longer available."
      :code==="AUTH_REQUIRED"?"Sign in with the email that received this invitation."
      :code==="CASE_UNAVAILABLE"||code==="NOT_MEDICAL_STAFF"?"This invitation does not match your signed-in email or is no longer available."
      :"The secure request could not be opened. Try again or contact People Support.";
    return `<div class="card login-card medical-return"><div class="mini-l">Secure document return</div><h2 class="section">Invitation unavailable</h2><div class="banner err">${esc(copy)}</div>${!['INVITE_EXPIRED','NOT_FOUND','CASE_UNAVAILABLE','NOT_MEDICAL_STAFF'].includes(code)?'<button class="btn sm ghost" onclick="renderMedicalInviteInto(document.getElementById(\'app\'),true)">Retry</button>':''}<p class="note-sm">For privacy, this page does not reveal case details when access fails.</p></div>`;
  }
  const request=medicalInvite.request||{};
  return `<div class="card login-card medical-return"><div class="mini-l">Secure document return</div><h2 class="section">Upload requested documents</h2><div class="banner info"><b>${esc(request.requestKind==='fmla'?'Medical leave':'Accommodation')} request ${esc(request.caseRef||'')}</b><br>${request.dueAt?`Requested by ${fmt(request.dueAt)}. This is an administrative follow-up date, not an automatic denial date.`:'No requested-by date is currently shown.'}</div><p>You may upload a provider letter or another supported PDF, image, or Word document. A particular blank form or signature is not required by this page.</p><label for="medical-return-files">Documents</label><input id="medical-return-files" type="file" multiple accept=".pdf,.png,.jpg,.jpeg,.doc,.docx" onchange="setMedicalReturnFiles(this.files)"><div class="row"><div class="col"><span class="mini-l">Document kind</span><select id="medical-return-kind"><option value="provider_note">Provider letter</option><option value="accommodation">Accommodation document</option><option value="fmla">Medical leave document</option><option value="other">Other requested document</option></select></div><div class="col"><span class="mini-l">Display label (optional)</span><input id="medical-return-label" maxlength="120" type="text" autocomplete="off"></div></div><button class="btn" ${medicalInvite.busy?'disabled aria-busy="true"':''} onclick="submitMedicalReturnFiles()">${medicalInvite.busy?'Uploading…':'Upload securely'}</button>${medicalInvite.error?`<div class="banner err">${esc(medicalInvite.error.message||medicalInvite.error)}</div>`:""}${medicalInvite.status==="complete"?'<div class="banner ok">Your document was uploaded. You may add another document or close this tab.</div>':''}${medicalInvite.documents.length?`<div class="divider"></div><b>Documents received for this request</b>${medicalInvite.documents.map(d=>`<div class="task"><span>${esc(d.label||'Document')}<span class="muted" style="font-size:11px"> · ${esc(d.kind||'')} · ${fmtBytes(d.sizeBytes)}</span></span><span class="chip">received</span></div>`).join('')}`:''}<p class="note-sm">This page grants access only to this return request. The invitation stays in memory for this tab and is cleared when you sign out.</p></div>`;
}
async function renderMedicalInviteInto(el,retry=false){
  if(!medicalInviteToken||!session)return;
  if(retry){medicalInvite.status="";medicalInvite.error="";medicalInvite.generation+=1;}
  if(!medicalInvite.status){medicalInvite.status="loading";el.innerHTML=medicalInviteHtml();const token=medicalInviteToken,epoch=sessionEpoch,userId=session.user.id,generation=medicalInvite.generation;const result=await medicalAction({action:"redeem_return_invite",token});if(token!==medicalInviteToken||epoch!==sessionEpoch||session?.user?.id!==userId||generation!==medicalInvite.generation)return;if(result.error){medicalInvite.status="error";medicalInvite.error=result.error;}else{medicalInvite.status="ready";medicalInvite.error="";medicalInvite.request=result.data?.request||null;medicalInvite.documents=result.data?.documents||[];}if(el.isConnected&&medicalInviteToken===token){el.innerHTML=medicalInviteHtml();hardenMedicalFileInputs(el);}return;}el.innerHTML=medicalInviteHtml();hardenMedicalFileInputs(el);
}
function setMedicalReturnFiles(files){medicalInvite.files=Array.from(files||[]);medicalInvite.error="";if(medicalInvite.status==="complete")medicalInvite.status="ready";}
async function submitMedicalReturnFiles(){
  const files=[...medicalInvite.files];if(!files.length){medicalInvite.error={message:"Choose at least one PDF, image, or Word document."};$("app").innerHTML=medicalInviteHtml();return;}const invalid=files.find(f=>!medicalFileInfo(f).valid);if(invalid){medicalInvite.error={message:`${invalid.name} is empty, too large, or has an unsupported file type.`};$("app").innerHTML=medicalInviteHtml();return;}
  const token=medicalInviteToken,epoch=sessionEpoch,userId=session?.user?.id,generation=medicalInvite.generation,kind=$("medical-return-kind")?.value||"other",label=($("medical-return-label")?.value||"").trim();medicalInvite.busy=true;medicalInvite.error="";$("app").innerHTML=medicalInviteHtml();const current=()=>token===medicalInviteToken&&epoch===sessionEpoch&&session?.user?.id===userId&&generation===medicalInvite.generation;
  try{for(const file of files){const info=medicalFileInfo(file),requestId=crypto.randomUUID();const prepared=await medicalAction({action:"prepare_return_upload",token,requestId,file:{name:file.name,type:info.type,size:file.size},kind,...(label?{label}:{})});if(!current())return;if(prepared.error)throw prepared.error;const upload=prepared.data?.file;if(!upload?.bucket||!upload?.uploadPath||!upload?.token)throw new Error("The private upload authorization was unavailable.");const uploaded=await sb.storage.from(upload.bucket).uploadToSignedUrl(upload.uploadPath,upload.token,file,{contentType:info.type});if(!current())return;if(uploaded.error)throw uploaded.error;const committed=await medicalAction({action:"commit_return_upload",token,requestId,uploadId:prepared.data.uploadId});if(!current())return;if(committed.error)throw committed.error;if(committed.data)medicalInvite.documents=[committed.data,...medicalInvite.documents];}medicalInvite.files=[];medicalInvite.busy=false;medicalInvite.status="complete";$("app").innerHTML=medicalInviteHtml();}catch(error){if(current()){medicalInvite.busy=false;medicalInvite.error={message:error?.message||"Upload failed. Retry from the original file."};medicalInvite.status="ready";$("app").innerHTML=medicalInviteHtml();}}
}

function render(){
  renderUserBox(); renderNav();
  const el = $("app");
  if(!session){ el.innerHTML = renderLogin(); return; }
  if(medicalInviteToken){ void renderMedicalInviteInto(el); return; }
  if((view==="dashboard"||view==="lookup") && !isHandler) view="home";
  if(view==="home"){ el.innerHTML = renderHome(); }
  else if(view==="employee-test"){ el.innerHTML = isHandler ? renderEmployeeTest() : renderHome(); }
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
