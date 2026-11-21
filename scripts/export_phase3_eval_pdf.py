#!/usr/bin/env python3
"""Generate the public synthetic-only Phase 3 IT113 evaluation brief.
Run: python scripts/export_phase3_eval_pdf.py
Dependency: pip install reportlab
No Supabase connection, credential or live event is used.
"""
from pathlib import Path
import json
from hashlib import sha256
from reportlab.pdfgen.canvas import Canvas
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether, HRFlowable

ROOT=Path(__file__).resolve().parents[1]
WEB=ROOT/'public'/'assessment'
MODEL=json.loads((WEB/'model_summary.json').read_text())
EVIDENCE=json.loads((WEB/'evidence.json').read_text())
MANIFEST=json.loads((WEB/'phase3_manifest.json').read_text())
assert EVIDENCE['not_live_inference'] is True and EVIDENCE['contains_real_personal_data'] is False
assert MANIFEST['live_inference'] is False and MANIFEST['contains_private_data'] is False
assert sha256((WEB/'model_summary.json').read_bytes()).hexdigest()==MANIFEST['metadata_sha256']
assert sha256((WEB/'evidence.json').read_bytes()).hexdigest()==MANIFEST['evidence_sha256']
assert MODEL['dataset']['test_rows']==sum(sum(row) for row in MODEL['xgboost']['confusion_matrix'])

D=MODEL['dataset'];X=MODEL['xgboost'];A=MODEL['autoencoder'];F=MODEL['risk_fusion']
PDF=WEB/'it113_model_evaluation.pdf'
PURPLE=colors.HexColor('#6439A0');NAVY=colors.HexColor('#1B1431');TEXT=colors.HexColor('#2F2640');MUTED=colors.HexColor('#726782');LIGHT=colors.HexColor('#F3EEFA');GREEN=colors.HexColor('#E0F5EA');PINK=colors.HexColor('#FCEDF2')
styles=getSampleStyleSheet()
styles.add(ParagraphStyle(name='CoverKicker',fontName='Helvetica-Bold',fontSize=10,leading=14,textColor=PURPLE,spaceAfter=16))
styles.add(ParagraphStyle(name='CoverTitle',fontName='Helvetica-Bold',fontSize=27,leading=32,textColor=NAVY,spaceAfter=14))
styles.add(ParagraphStyle(name='BodyP',fontName='Helvetica',fontSize=9.1,leading=14.4,textColor=TEXT,spaceAfter=9))
styles.add(ParagraphStyle(name='BodySmall',fontName='Helvetica',fontSize=8,leading=12,textColor=TEXT,spaceAfter=7))
styles.add(ParagraphStyle(name='SmallMuted',fontName='Helvetica',fontSize=7.5,leading=11,textColor=MUTED,spaceAfter=7))
styles.add(ParagraphStyle(name='HeadingP',fontName='Helvetica-Bold',fontSize=15,leading=20,textColor=NAVY,spaceBefore=12,spaceAfter=10))
styles.add(ParagraphStyle(name='SubHeadingP',fontName='Helvetica-Bold',fontSize=10,leading=15,textColor=PURPLE,spaceBefore=10,spaceAfter=6))
styles.add(ParagraphStyle(name='KpiVal',fontName='Helvetica-Bold',fontSize=17,leading=22,textColor=NAVY,alignment=TA_CENTER))
styles.add(ParagraphStyle(name='KpiCap',fontName='Helvetica',fontSize=7.5,leading=10,textColor=MUTED,alignment=TA_CENTER))
styles.add(ParagraphStyle(name='THead',fontName='Helvetica-Bold',fontSize=7.6,leading=10,textColor=colors.white))
styles.add(ParagraphStyle(name='TCell',fontName='Helvetica',fontSize=7.2,leading=10,textColor=TEXT))
styles.add(ParagraphStyle(name='TCellSm',fontName='Helvetica',fontSize=6.8,leading=9,textColor=TEXT))
styles.add(ParagraphStyle(name='Note',fontName='Helvetica',fontSize=8.4,leading=12,textColor=NAVY,spaceAfter=0))

story=[]
P=lambda t,sty='BodyP':Paragraph(str(t),styles[sty])
def heading(t):story.append(P(t,'HeadingP'))
def sub(t):story.append(P(t,'SubHeadingP'))
def body(t):story.append(P(t))
def note(t):
  table=Table([[P(t,'Note')]],colWidths=[172*mm])
  table.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,-1),LIGHT),('BOX',(0,0),(-1,-1),.6,colors.HexColor('#D7C6E7')),('LEFTPADDING',(0,0),(-1,-1),12),('RIGHTPADDING',(0,0),(-1,-1),12),('TOPPADDING',(0,0),(-1,-1),10),('BOTTOMPADDING',(0,0),(-1,-1),10)]))
  story.append(table);story.append(Spacer(1,6*mm))
def table(rows,widths,header=True,cell='TCell',padding=7):
  out=[]
  for i,row in enumerate(rows): out.append([P(v,'THead' if i==0 and header else cell) for v in row])
  t=Table(out,colWidths=widths,repeatRows=1 if header else 0,hAlign='LEFT')
  ts=[('VALIGN',(0,0),(-1,-1),'TOP'),('LEFTPADDING',(0,0),(-1,-1),padding),('RIGHTPADDING',(0,0),(-1,-1),padding),('TOPPADDING',(0,0),(-1,-1),padding),('BOTTOMPADDING',(0,0),(-1,-1),padding),('LINEBELOW',(0,0),(-1,-1),.35,colors.HexColor('#E7DFF1'))]
  if header:ts += [('BACKGROUND',(0,0),(-1,0),NAVY),('ROWBACKGROUNDS',(0,1),(-1,-1),[colors.white,colors.HexColor('#FAF8FC')])]
  else:ts += [('BACKGROUND',(0,0),(-1,-1),LIGHT)]
  t.setStyle(TableStyle(ts));story.append(t);story.append(Spacer(1,4*mm))

def page(canvas,doc):
  w,h=A4
  canvas.setFillColor(NAVY);canvas.rect(0,h-13*mm,w,13*mm,fill=1,stroke=0)
  canvas.setFillColor(colors.white);canvas.setFont('Helvetica-Bold',8);canvas.drawString(19*mm,h-8.7*mm,'FORTRESSAUTH  /  IT113 RESEARCH EVIDENCE')
  canvas.setStrokeColor(colors.HexColor('#E5DDEF'));canvas.line(19*mm,18*mm,w-19*mm,18*mm)
  canvas.setFillColor(MUTED);canvas.setFont('Helvetica',7.2)
  canvas.drawString(19*mm,13*mm,'Synthetic model evaluation  |  No personal data  |  Not a live detection report')
  canvas.drawRightString(w-19*mm,13*mm,f'Page {doc.page}')

story.append(Spacer(1,16*mm))
story.append(P('IT113 / INFORMATION ASSURANCE AND SECURITY 2','CoverKicker'))
story.append(P('FortressAuth: AI/ML Model Evaluation &amp; Threat Mitigation Brief','CoverTitle'))
body('Phase 3 technical evidence brief based on the actual Phase 1 model-evaluation artifacts. It describes what the trained models achieved on held-out synthetic data and how the results should guide controlled security decisions.')
note('<b>Academic evidence boundary.</b> All numerical results here come from reproducible synthetic examples. This is NOT a production security audit, live attack trace, or the final Phase 5 report. The private administrator database was not accessed.')

def kpi(label,value):return [P(value,'KpiVal'),P(label,'KpiCap')]
kpis=[kpi('Test accuracy',f'{X["accuracy"]*100:.2f}%'),kpi('Macro F1',f'{X["macro_f1"]*100:.2f}%'),kpi('Features',str(len(D['features']))),kpi('Behavior classes',str(len(D['classes'])))]
kt=Table([kpis],colWidths=[43*mm]*4)
kt.setStyle(TableStyle([('BOX',(0,0),(-1,-1),.7,colors.HexColor('#DBCBE8')),('INNERGRID',(0,0),(-1,-1),.5,colors.HexColor('#DBCBE8')),('BACKGROUND',(0,0),(-1,-1),LIGHT),('TOPPADDING',(0,0),(-1,-1),13),('BOTTOMPADDING',(0,0),(-1,-1),13)]));story.append(kt)
heading('Research design and algorithm selection')
body('<b>XGBoost</b> is a supervised classifier for seven labeled behavioral categories. An <b>autoencoder</b>, trained on normal samples, provides a complementary reconstruction-error anomaly signal. A deterministic rule engine can contribute additional evidence during an authenticated live assessment. The hybrid score is a weighted combination of the three signals, not a guarantee of attacker intent.')
sub('Separated datasets')
table([['Split','Rows','Purpose'],['Training',f'{D["training_rows"]:,}','Fit the models'],['Validation',f'{D["validation_rows"]:,}','Set anomaly threshold independently'],['Test',f'{D["test_rows"]:,}','Final held-out metrics']], [42*mm,30*mm,100*mm])
sub('Model identity and provenance')
body(f'Model fingerprint prefix: <b>{MANIFEST["classifier_autoencoder_version"]}</b>. Training script SHA-256: <font size="8">{MANIFEST["training_script_sha256"]}</font>. Model evaluation metadata and evidence are bundled as JSON with the application.')

story.append(PageBreak())
heading('Dataset assessment and quality validation')
body('The controlled dataset contains generated request-rate, login-pressure, endpoint-probe, security-event and behavioral-context features. No passwords, cookies, QR secrets, authorization headers or real user content are needed for the published study.')
counts=D['class_counts']['test']
table([['Behavior category','Independent test records']]+[[name.replace('_',' ').title(),f'{counts[name]:,}'] for name in D['classes']],[101*mm,71*mm])
issues=sum(v for segment in D['data_quality_invariant_violations'].values() for v in segment.values())
note(f'<b>Data quality:</b> {issues} invariant violations are recorded across train, validation and test splits after correction. The generator checks rolling-window relationships, finite/nonnegative features, and bounded indicators. Internal validity does not establish external realism.')
heading('Seven-class XGBoost confusion matrix')
body('Rows indicate the known true class; columns indicate the model prediction. Diagonal values represent correct classifications.')
short=['NORM','BRUT','CRED','RECO','WEB','MFA','SESS']
rows=[['TRUE \\ PRED']+short]
for i,row in enumerate(X['confusion_matrix']):rows.append([short[i]]+[str(v) for v in row])
table(rows,[28*mm]+[20.57*mm]*7,cell='TCellSm',padding=5)
correct=sum(row[i] for i,row in enumerate(X['confusion_matrix']))
body(f'<b>Correct predictions:</b> {correct:,} / {D["test_rows"]:,}. <b>Incorrect predictions:</b> {D["test_rows"]-correct:,}. These values reconcile with the reported accuracy. Errors are relevant because misclassification can lead to wrong security recommendations.')

story.append(PageBreak())
heading('Classifier performance and error analysis')
table([['Class','Precision','Recall','F1','Support']]+[[name.replace('_',' ').title(), f'{X["classification_report"][name]["precision"]*100:.2f}%',f'{X["classification_report"][name]["recall"]*100:.2f}%',f'{X["classification_report"][name]["f1-score"]*100:.2f}%',f'{int(X["classification_report"][name]["support"]):,}'] for name in D['classes']],[54*mm,29*mm,29*mm,29*mm,31*mm],cell='TCellSm',padding=6)
errors=[]
for i,row in enumerate(X['confusion_matrix']):
 for j,v in enumerate(row):
  if i!=j and v:errors.append((v,D['classes'][i],D['classes'][j]))
errors.sort(reverse=True)
sub('Most common misclassifications')
table([['Actual class','Predicted as','Count']]+[[a.replace('_',' ').title(),b.replace('_',' ').title(),str(count)] for count,a,b in errors[:5]],[70*mm,72*mm,30*mm])
heading('Autoencoder evaluation')
binary=A['test_confusion_matrix_binary_normal_then_anomaly']
table([['Metric','Held-out result'],['Test anomaly recall',f'{A["holdout_anomaly_recall"]*100:.2f}%'],['Normal false-positive rate',f'{A["holdout_normal_false_positive_rate"]*100:.2f}%'],['Anomaly precision',f'{A["test_anomaly_precision"]*100:.2f}%'],['Anomaly F1',f'{A["test_anomaly_f1"]*100:.2f}%'],['ROC AUC',f'{A["test_anomaly_roc_auc"]:.4f}'],['Validation threshold (p99)',f'{A["threshold_p99"]:.4f}'],['Test normal / anomaly matrix',f'[[{binary[0][0]}, {binary[0][1]}], [{binary[1][0]}, {binary[1][1]}]]']], [90*mm,82*mm])
note('The anomaly threshold was selected using normal records in the validation split, not tuned against the final test split. Anomaly score is not a calibrated probability that an individual is malicious. Feature importance is global and does not explain causality for one specific prediction.')

heading('Threat-linked mitigation matrix')
mitigations=[
 ('NORMAL','Compare with historic baseline; avoid penalizing weak isolated indicators','Maintain minimized monitoring and periodic trend review'),
 ('BRUTE_FORCE','Confirm repeated failed logins and account targeting','Rate limits, account cooldowns, MFA'),
 ('CREDENTIAL_STUFFING','Correlate usernames, IP pressure and sign-in outcomes','MFA, rate limits and compromised-password screening'),
 ('RECONNAISSANCE','Review scanned paths and request context','Restrict sensitive routes, patch, audit probes'),
 ('WEB_ATTACK','Review sanitized requests and validate affected endpoint','Parameterized SQL, input validation, output encoding'),
 ('MFA_ABUSE','Confirm repeated challenges and failed second factors','Attempt limits, bound challenges and expiry'),
 ('SESSION_ABUSE','Review session signals and CSRF failure logs','Session rotation, secure cookies and CSRF protection'),
]
table([['Behavior','Verification before response','Practical mitigation']]+[[a.replace('_',' ').title(),b,c] for a,b,c in mitigations],[38*mm,68*mm,66*mm],cell='TCellSm',padding=5)
heading('Interpretation boundaries and next steps')
for note_text in [
 'The original study uses generated, deliberately balanced class distributions; production incident rates and model performance remain unknown.',
 'A category label represents a learned behavior pattern, not a confirmed exploit, compromised account, malicious person or specific CVE.',
 'Recommendations require analyst confirmation and should follow least privilege, documented policy, appropriate rate limiting and incident response review.',
 'Public /assessment/ pages use precomputed synthetic evidence only. Live source IPs, event IDs, trace IDs and database queries remain in protected administrator workflows.',
 'Supabase migration and cloud verification were deferred during restoration. Phase 4 must validate real integrated behavior and errors in an authorized environment.',
 'The full academic methodology, ethics, presentation and final reporting are reserved for Phase 5.',
]:story.append(P('• '+note_text,'BodySmall'))
sub('Primary evidence inputs')
body('model_summary.json · evidence.json · phase3_manifest.json · ml-service/training/train_models.py. All are included in or directly generated from the FortressAuth project source archive.')

PDF.parent.mkdir(parents=True,exist_ok=True)
doc=SimpleDocTemplate(str(PDF), pagesize=A4,rightMargin=19*mm,leftMargin=19*mm,topMargin=21*mm,bottomMargin=23*mm,title='FortressAuth IT113 Synthetic Model Evaluation and Mitigation Brief',author='FortressAuth IT113 Project',subject='Reproducible synthetic-data model assessment')
doc.build(story,onFirstPage=page,onLaterPages=page)
print('Created',PDF,'bytes',PDF.stat().st_size)
