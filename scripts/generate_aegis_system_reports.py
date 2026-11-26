#!/usr/bin/env python3
"""Generate read-only Aegis AI research-report snapshots from saved synthetic artifacts.
Run at project root: python scripts/generate_aegis_system_reports.py
Requires reportlab for offline PDF authoring; does not access runtime data or retrain models.
"""
import json, html
from datetime import datetime, timezone
from pathlib import Path
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import SimpleDocTemplate, Paragraph, Table, TableStyle, Spacer, PageBreak, KeepTogether
from reportlab.lib import colors
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm

A=Path(__file__).resolve().parents[1]/'public'/'assessment'
s=json.loads((A/'model_summary.json').read_text())
e=json.loads((A/'evidence.json').read_text())
assert s['dataset']['type'].startswith('synthetic/') and e['not_live_inference'] and not e['contains_real_personal_data']
d,x,auto,r,hy=s['dataset'],s['xgboost'],s['autoencoder'],s['reproducibility'],s['risk_fusion']
classes=d['classes']; m=x['confusion_matrix']; ok=sum(m[i][i] for i in range(len(classes))); total=sum(sum(z) for z in m)
# Use a locally installed font; do not bundle or redistribute font files.
# Works on Linux and Windows (the project is commonly run on Windows).
font_pairs = [
    (Path('/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf'), Path('/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf')),
    (Path('C:/Windows/Fonts/arial.ttf'), Path('C:/Windows/Fonts/arialbd.ttf')),
]
FONT_NAME, FONT_BOLD = 'Helvetica', 'Helvetica-Bold'
for regular, bold in font_pairs:
    if regular.exists() and bold.exists():
        pdfmetrics.registerFont(TTFont('Aegis', str(regular)))
        pdfmetrics.registerFont(TTFont('Aegis-B', str(bold)))
        FONT_NAME, FONT_BOLD = 'Aegis', 'Aegis-B'
        break
INK=colors.HexColor('#20142d');PURPLE=colors.HexColor('#6b3d96');LAV=colors.HexColor('#f0eaf8');LINE=colors.HexColor('#d9cee9');MUTED=colors.HexColor('#63586d');WHITE=colors.white
pw,ph=A4; W=pw-36*mm
style={
 'cover':ParagraphStyle('cover',fontName=FONT_BOLD,fontSize=26,leading=34,textColor=INK,spaceAfter=14),
 'tag':ParagraphStyle('tag',fontName=FONT_BOLD,fontSize=8,leading=13,textColor=PURPLE,spaceAfter=12),
 'h1':ParagraphStyle('h1',fontName=FONT_BOLD,fontSize=16,leading=23,textColor=INK,spaceAfter=12,keepWithNext=True),
 'h2':ParagraphStyle('h2',fontName=FONT_BOLD,fontSize=11,leading=16,textColor=PURPLE,spaceBefore=12,spaceAfter=8,keepWithNext=True),
 'body':ParagraphStyle('body',fontName=FONT_NAME,fontSize=9.1,leading=15.1,textColor=INK,spaceAfter=10),
 'small':ParagraphStyle('small',fontName=FONT_NAME,fontSize=7.8,leading=12.5,textColor=MUTED,spaceAfter=9),
 'cell':ParagraphStyle('cell',fontName=FONT_NAME,fontSize=7.45,leading=11.15,textColor=INK),
 'th':ParagraphStyle('th',fontName=FONT_BOLD,fontSize=7.4,leading=11.25,textColor=WHITE),
 'number':ParagraphStyle('number',fontName=FONT_BOLD,fontSize=16,leading=22,textColor=PURPLE),
}
def P(t,kind='body',raw=False):return Paragraph(t if raw else html.escape(str(t)),style[kind])
def percent(v):return f'{100*float(v):.2f}%'
def pretty(t):return t.replace('_',' ').title().replace('Mfa','MFA')
def T(rows,widths,head=True):
    dat=[[P(v,'th' if head and i==0 else 'cell') for v in row] for i,row in enumerate(rows)]
    q=Table(dat,colWidths=widths,repeatRows=1 if head else 0,hAlign='LEFT')
    ts=[('VALIGN',(0,0),(-1,-1),'TOP'),('TOPPADDING',(0,0),(-1,-1),7),('BOTTOMPADDING',(0,0),(-1,-1),7),('LEFTPADDING',(0,0),(-1,-1),7),('RIGHTPADDING',(0,0),(-1,-1),7),('ROWBACKGROUNDS',(0,1 if head else 0),(-1,-1),[WHITE,LAV]),('LINEBELOW',(0,-1),(-1,-1),.5,LINE)]
    if head:ts.append(('BACKGROUND',(0,0),(-1,0),INK))
    q.setStyle(TableStyle(ts));return q

def KPI(items):
    dat=[[ [P(v,'number'),P(k,'small')] for k,v in items]]
    q=Table(dat,colWidths=[W/len(items)]*len(items))
    q.setStyle(TableStyle([('VALIGN',(0,0),(-1,-1),'TOP'),('BACKGROUND',(0,0),(-1,-1),LAV),('BOX',(0,0),(-1,-1),.6,LINE),('INNERGRID',(0,0),(-1,-1),.6,LINE),('TOPPADDING',(0,0),(-1,-1),12),('LEFTPADDING',(0,0),(-1,-1),10)]))
    return q

def footer(can,doc):
    can.saveState();can.setFillColor(INK);can.rect(0,ph-13*mm,pw,13*mm,stroke=0,fill=1)
    can.setFillColor(WHITE);can.setFont(FONT_BOLD,8);can.drawString(18*mm,ph-8.1*mm,'AEGIS AI  /  SECURITY RESEARCH')
    can.setFont(FONT_NAME,7);can.drawRightString(pw-18*mm,ph-8.1*mm,'SAVED MODEL SNAPSHOT')
    can.setStrokeColor(LINE);can.line(18*mm,14*mm,pw-18*mm,14*mm)
    can.setFillColor(MUTED);can.setFont(FONT_NAME,7);can.drawString(18*mm,9.3*mm,'Saved benchmark · Excludes current assessment feed · Advisory only')
    can.drawRightString(pw-18*mm,9.3*mm,f'{doc.page:02d}');can.restoreState()

def build(path,story,label):
    doc=SimpleDocTemplate(str(path),pagesize=A4,leftMargin=18*mm,rightMargin=18*mm,topMargin=22*mm,bottomMargin=20*mm,title='Aegis AI - '+label,author='Aegis AI System')
    doc.build(story,onFirstPage=footer,onLaterPages=footer)

mit=[
 ('Normal','Confirm expected baseline and investigate unusual deviations','Baseline monitoring, limited audit data; avoid unnecessary enforcement'),
 ('Brute Force','Correlate failed-login bursts and affected account/source context','Per-account and source throttling, MFA, safe cooldown'),
 ('Credential Stuffing','Review attempts across multiple accounts and sign-in outcomes','Rate limits, MFA and compromised-password defenses'),
 ('Reconnaissance','Check discovered routes, sensitive endpoint probes and authorization','Least privilege, patching and minimized exposed routes'),
 ('Web Attack','Inspect sanitized suspicious requests and affected application endpoints','Parameterized SQL, output encoding, input checks and CSRF controls'),
 ('MFA Abuse','Validate repeated challenges, denials and expirations','Challenge binding, retry caps, expiration and alerting'),
 ('Session Abuse','Investigate session anomalies and state-changing request failures','Session rotation, secure cookies, CSRF validation and timeout'),
]
errors=sorted([(m[i][j],pretty(classes[i]),pretty(classes[j])) for i in range(7) for j in range(7) if i!=j and m[i][j]],reverse=True)
labels=['NOR','BRU','CRE','REC','WEB','MFA','SES']
conf=[['Actual / pred.']+labels]+[[labels[i]]+[str(z) for z in m[i]] for i in range(7)]
per=[['Behavior','Precision','Recall','F1','Support']]+[[pretty(k),percent(x['classification_report'][k]['precision']),percent(x['classification_report'][k]['recall']),percent(x['classification_report'][k]['f1-score']),f'{int(x["classification_report"][k]["support"]):,}'] for k in classes]

intro=[Spacer(1,17*mm),P('AEGIS AI   /   SAVED RESEARCH SNAPSHOT','tag'),P('Security Assessment &amp;<br/>Threat Analysis Report','cover',raw=True),P('Versioned findings, synthetic behavior classifications, model evaluation and review-first mitigation guidance.'),Spacer(1,9*mm),KPI([('Held-out accuracy',percent(x['accuracy'])),('Records tested',f'{total:,}'),('Behavior classes','7')]),Spacer(1,14*mm),P('Evidence basis','h2'),P('This snapshot is generated from saved model_summary.json and evidence.json artifacts. It does not contain current public research feed records, private CSV tests, or operational security logs.'),P('Interpretation boundary','h2'),P('The model can describe suspicious synthetic patterns, but does not verify an attack, an exploitable weakness, missing MFA or rate limiting, or successful remediation.'),Spacer(1,12*mm),P('Generated '+datetime.now(timezone.utc).strftime('%d %b %Y')+' UTC   |   Controlled synthetic research','small'),Spacer(1,11*mm),P('Snapshot contents and exclusions','h2'),T([['Included in saved benchmark','Excluded from this snapshot'],['10,500 held-out labeled synthetic test records; classifier and anomaly metrics','Current public findings, private CSV sessions, operational activity or live attack events'],['13 purposefully selected saved examples; class-specific defensive guidance','Real-world vulnerability confirmation, deployed control effectiveness or field detection accuracy']],[W*.50,W*.50]),Spacer(1,10*mm),P('Reference sources','h2'),P('NIST SP 800-61 Rev. 3: https://csrc.nist.gov/pubs/sp/800/61/r3/final','small'),P('OWASP Cheat Sheet Series: https://cheatsheetseries.owasp.org/','small'),PageBreak()]

main=intro+[
 P('1  Executive findings','h1'),P(f'The saved seven-class XGBoost model correctly classified {ok:,} of {total:,} held-out synthetic behavior records ({percent(x["accuracy"])} accuracy). It made {total-ok:,} errors. A normal-only reconstruction autoencoder measures anomalous deviation independently; a weighted hybrid risk system supports triage.'),
 KPI([('Correct labels',f'{ok:,}'),('Errors',f'{total-ok:,}'),('Macro F1',percent(x['macro_f1']))]),
 P('Key observed limitations','h2'),
 P(f'Largest confusion: {errors[0][1]} predicted as {errors[0][2]} ({errors[0][0]} records). A second notable confusion was {errors[1][1]} predicted as {errors[1][2]} ({errors[1][0]} records). These are observed on simulated data, not confirmed incidents.'),
 P('The autoencoder achieves '+percent(auto['holdout_anomaly_recall'])+' synthetic anomaly recall and '+percent(auto['holdout_normal_false_positive_rate'])+' normal false positives. The near-perfect anomaly results require especially careful interpretation because test patterns are artificial.'),
 P('Report-source distinction','h2'),P('This baseline PDF is a fixed report of saved model validation. The Research Reports interface separately builds the current assessment report from whichever public findings or private tests are selected, and supports their JSON, CSV and Print-to-PDF exports.'),
 T([['Supported by evidence','Not demonstrated'],['Model scores, synthetic labels, confusion data and category-linked control guidance','Real attack attribution, production detection rates, exploited vulnerabilities or effectiveness of deployed countermeasures']],[W/2]*2),Spacer(1,11*mm),
 P('2  Data description and reproducibility','h1'),P(d['note']),KPI([('Training',f'{d["training_rows"]:,}'),('Validation',f'{d["validation_rows"]:,}'),('Test',f'{d["test_rows"]:,}'),('Features',str(len(d['features'])))]),Spacer(1,9*mm),
 P('Seven synthetic classes','h2'),T([['Class','Test support','Source']]+[[pretty(k),'1,500','Generated held-out class'] for k in classes],[W*.33,W*.21,W*.46]),
 P('Feature categories','h2'),T([['Group','Examples'],['Request and navigation signals','requests_1m; requests_5m; unique_paths_5m; avg_request_interval_5m'],['Authentication behavior','failed_logins_5m; failed_logins_15m; unique_usernames_15m; successful_logins_15m'],['Application and access-control events','sensitive_path_probes_15m; csrf_failures_15m; suspicious_requests_15m; auth_rejections_15m'],['Context signals','ua_changes_15m; off_hours; method_anomalies_15m']],[W*.29,W*.71]),
 P('Seeds: train 113 / validation 2113 / test 9113. A controlled test shift was applied within the same generator family; this is not external network validation.','small'),Spacer(1,11*mm),
 P('3  XGBoost classification results','h1'),KPI([('Accuracy',percent(x['accuracy'])),('Precision',percent(x['macro_precision'])),('Recall',percent(x['macro_recall'])),('Macro F1',percent(x['macro_f1']))]),Spacer(1,12*mm),
 KeepTogether([P('Seven-class confusion matrix','h2'),P('Rows indicate actual synthetic labels; columns indicate model predictions. Diagonal values are correct classifications.','small'),T(conf,[W*.20]+[W*.80/7]*7)]),Spacer(1,10*mm),
 P('Largest error pairs','h2'),T([['True synthetic label','Predicted label','Cases']]+[[a,b,str(n)] for n,a,b in errors[:5]],[W*.40,W*.40,W*.20]),Spacer(1,11*mm),
 P('4  Per-class findings and explanations','h1'),T(per,[W*.34,W*.18,W*.16,W*.16,W*.16]),Spacer(1,12*mm),
 P('Interpretation','h2'),P('Credential Stuffing is sometimes misclassified as Brute Force. Session Abuse and Web Attack also overlap in a subset of simulated examples. The results suggest that these learned behavior classes are partially confusable on the generated benchmark.'),
 P('Global feature importance, not individual attribution','h2'),T([['Training feature','Relative score']]+[[name,f'{val*100:.2f}%'] for name,val in x['top_feature_importance'][:7]],[W*.67,W*.33]),
 P('Global feature importance does not identify which feature caused one case prediction. Threshold exceedances are separate supporting indicators, not SHAP explanations or proof of an exploitable vulnerability.','small'),Spacer(1,11*mm),
 P('5  Anomaly score and hybrid risk','h1'),P('The normal-only MLPRegressor autoencoder reconstructs feature vectors and compares their reconstruction error with a threshold derived from normal validation observations.'),
 KPI([('Anomaly recall',percent(auto['holdout_anomaly_recall'])),('False-positive rate',percent(auto['holdout_normal_false_positive_rate'])),('Anomaly precision',percent(auto['test_anomaly_precision'])),('Cutoff',f"{auto['threshold_p99']:.4f}")]),Spacer(1,10*mm),
 P('Binary anomaly confusion matrix','h2'),T([['True class','Within threshold','Above threshold'],['Normal',str(auto['test_confusion_matrix_binary_normal_then_anomaly'][0][0]),str(auto['test_confusion_matrix_binary_normal_then_anomaly'][0][1])],['Synthetic anomaly',str(auto['test_confusion_matrix_binary_normal_then_anomaly'][1][0]),str(auto['test_confusion_matrix_binary_normal_then_anomaly'][1][1])]],[W*.4,W*.3,W*.3]),
 P('Illustrative hybrid risk weighting','h2'),T([['Rule indicators','XGBoost component','Anomaly signal'],[f"{100*hy['rule_weight']:.0f}%",f"{100*hy['xgboost_weight']:.0f}%",f"{100*hy['autoencoder_weight']:.0f}%"]],[W/3]*3),
 P('Classification score, anomaly deviation and composite risk are different measures and are not calibrated real-incident probabilities. The synthetic ROC AUC of 1.0000 is not a production performance claim.'),Spacer(1,11*mm),
 P('6  Selected saved evidence cases','h1'),P(f'The evidence bundle contains {len(e["examples"])} precomputed held-out examples. This small, intentionally selected set contains correct and incorrect predictions, and should not be presented as representative test-set accuracy.'),
 T([['Saved example','True label','Prediction','Score','Match']]+[[q['id'],pretty(q['true_label']),pretty(q['predicted_label']),percent(q['confidence']),'Yes' if q['correct'] else 'No'] for q in e['examples']],[W*.28,W*.22,W*.23,W*.16,W*.11]),
 Spacer(1,8*mm),P('What the examples teach','h2'),P('Some synthetic examples are confidently misclassified. Model confidence cannot establish that activity is truly malicious. Genuine root-cause interpretation requires separate attribution methods and review of authorized source evidence.'),Spacer(1,11*mm),
 P('7  Evidence-linked mitigation guidance','h1'),P('The following mapping is review-first defensive guidance linked to the model categories. It is not evidence that a particular protection is absent or that an attack occurred.'),
 T([['Pattern','Evidence to verify','Potential controls']]+[list(row) for row in mit],[W*.18,W*.39,W*.43]),Spacer(1,10*mm),
 P('8  Provenance and research limitations','h1'),
 P('Analyst validation procedure','h2'),P('1. Confirm supporting behavior counts against authorized data.  2. Review applicable configuration and policy.  3. Select proportionate safeguards, considering legitimate users.  4. Validate with controlled, non-destructive tests.  5. Record uncertainty and review outcome.'),
 P('Guidance aligns with relevant OWASP Authentication, MFA, SQLi, XSS, CSRF, Session Management and Authorization Cheat Sheets, and NIST SP 800-61 Rev. 3.','small'),
  P('What is established','h2'),P('The saved benchmark reproducibly demonstrates behavior classification, anomaly analysis, selected error cases, and a category-linked security recommendation workflow on synthetic numeric inputs.'),
  P('What is not established','h2'),P('No real-world attack rate, operational exploit, real missing control, credential compromise, deployment enforcement result or field false-positive rate has been measured. Class-balanced generation and shared generator assumptions may overstate generalization.'),
  P('Evidence identifiers','h2'),T([['Artifact','Recorded evidence'],['Model summary','model_summary.json'],['Precomputed examples','evidence.json'],['Training SHA-256',r['training_script_sha256']],['Model fingerprint prefix','24112c5d14aaeac3'],['Random state',str(r['random_state'])]],[W*.37,W*.63]),
  P('Before operational use','h2'),T([['Required external check','Why it matters'],['Validate on legitimately collected and independently labeled data','The synthetic test set cannot establish field accuracy or deployment false-positive rates.'],['Correlate alerts with authorized logs and reviewed configurations','Classifications and thresholds cannot establish that MFA, throttling or other controls are absent.'],['Measure defensive-control effectiveness in an approved environment','A recommended mitigation is not proof that the deployed control works or that risk is eliminated.']],[W*.45,W*.55]),
  P("This saved snapshot is separate from the page's dynamically generated, selected-finding report.",'small')
]

brief=[Spacer(1,17*mm),P('AEGIS AI   /   MODEL EVIDENCE SNAPSHOT','tag'),P('Model Evaluation &amp;<br/>Threat Mitigation Brief','cover',raw=True),P('Technical figures from the saved synthetic XGBoost/autoencoder benchmark and corresponding review-first security controls.'),Spacer(1,10*mm),KPI([('Accuracy',percent(x['accuracy'])),('Macro F1',percent(x['macro_f1'])),('Anomaly recall',percent(auto['holdout_anomaly_recall']))]),Spacer(1,16*mm),P('Evaluation source','h2'),P(f'{d["training_rows"]:,} training, {d["validation_rows"]:,} validation and {d["test_rows"]:,} held-out synthetic rows; 20 numeric features and seven behavior labels.'),P('Saved artifact sources: model_summary.json and evidence.json. Report generated '+datetime.now(timezone.utc).strftime('%d %b %Y')+' UTC.','small'),Spacer(1,11*mm),P('Reporting boundary','h2'),T([['Saved model snapshot','Current selected findings'],['This PDF verifies the precomputed training/test benchmark and recommended safeguards.','Current assessments are available separately in the live Research Reports preview and its Print/CSV/JSON exports.']],[W*.50,W*.50]),Spacer(1,12*mm),P('Research provenance','h2'),P(f'{len(e["examples"])} selected precomputed held-out examples; model fingerprint 24112c5d14aaeac3; training random state 113; synthetic class-balanced generator. No real incident records or successful exploit evidence.'),P('References: OWASP Cheat Sheet Series, https://cheatsheetseries.owasp.org/ ; NIST SP 800-61 Rev. 3, https://csrc.nist.gov/pubs/sp/800/61/r3/final.','small'),PageBreak(),
 P('1  Classification verification','h1'),KPI([('Accuracy',percent(x['accuracy'])),('Precision',percent(x['macro_precision'])),('Recall',percent(x['macro_recall'])),('F1',percent(x['macro_f1']))]),Spacer(1,11*mm),P('Confusion matrix: true by predicted','h2'),T(conf,[W*.20]+[W*.80/7]*7),Spacer(1,12*mm),P(f'Correct: {ok:,}/{total:,}. Incorrect: {total-ok:,}. Most frequent errors: Credential Stuffing as Brute Force (130), Session Abuse as Web Attack (83), and Web Attack as Session Abuse (36).'),Spacer(1,12*mm),
 P('2  Per-class and autoencoder results','h1'),T(per,[W*.34,W*.18,W*.16,W*.16,W*.16]),Spacer(1,10*mm),P('Anomaly detection metrics','h2'),KPI([('Recall',percent(auto['holdout_anomaly_recall'])),('Normal false-positive rate',percent(auto['holdout_normal_false_positive_rate'])),('Precision',percent(auto['test_anomaly_precision'])),('Cutoff',f"{auto['threshold_p99']:.4f}")]),Spacer(1,12*mm),P('The normal-only threshold was selected from the 99th percentile of 1,000 normal validation rows. Synthetic anomaly/normal confusion: '+str(auto['test_confusion_matrix_binary_normal_then_anomaly'])+'. These figures are not calibrated attack likelihoods.'),P(f"Illustrative composite risk: rule {100*hy['rule_weight']:.0f}%, classifier-related {100*hy['xgboost_weight']:.0f}%, anomaly {100*hy['autoencoder_weight']:.0f}%."),Spacer(1,12*mm),
 P('3  Threat-specific defensive review','h1'),P('Potential safeguards require independent verification of the actual environment; model classes alone cannot prove vulnerabilities or control absence.'),T([['Category','Evidence review','Controls to consider']]+[list(row) for row in mit],[W*.18,W*.39,W*.43]),Spacer(1,6*mm),P('Analyst interpretation','h2'),P('This category-level guidance is intended for human review. Confirm relevant configuration and behavior with authorized evidence before declaring a weakness or considering an operational response.')]

assert len(m)==len(classes) and 0 <= ok <= total, 'Invalid saved evaluation matrix'
build(A/'it113_final_report_draft.pdf',main,'Saved Security Assessment and Threat Analysis Report')
build(A/'it113_model_evaluation.pdf',brief,'Saved Model Evaluation and Mitigation Brief')
for name in ('it113_final_report_draft.pdf','it113_model_evaluation.pdf'):
 print(name,(A/name).stat().st_size)
