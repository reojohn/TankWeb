#!/usr/bin/env python3
"""Regenerate academic D/E drafts from FortressAuth public *synthetic* saved metrics.
No backend, user data or secrets are read. Requires reportlab and python-pptx.
Output is intentionally labeled a draft until hosted screenshots and team details are supplied.
"""
import json
from pathlib import Path
from xml.sax.saxutils import escape
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.units import mm
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether, HRFlowable
from pptx import Presentation
from pptx.util import Inches, Pt
from pptx.dml.color import RGBColor
from pptx.enum.shapes import MSO_SHAPE

BASE = Path(__file__).resolve().parents[1]
PUBLIC = BASE / 'public' / 'assessment'
SUMMARY = json.loads((PUBLIC/'model_summary.json').read_text())
EVIDENCE = json.loads((PUBLIC/'evidence.json').read_text())
assert EVIDENCE.get('not_live_inference') is True and EVIDENCE.get('contains_real_personal_data') is False
D,X,A,R = (SUMMARY[k] for k in ('dataset','xgboost','autoencoder','reproducibility'))
assert len(D['features'])==20 and len(D['classes'])==7

HIGHLIGHT=colors.HexColor('#6D4AA8'); ACCENT=colors.HexColor('#4A927C'); NAVY=colors.HexColor('#1C1B35'); MID=colors.HexColor('#514A66'); LIGHT=colors.HexColor('#EFEAF5'); BG=colors.HexColor('#F7F4FA')
styles=getSampleStyleSheet()
styles.add(ParagraphStyle(name='CoverKicker',fontName='Helvetica-Bold',fontSize=10,leading=15,textColor=HIGHLIGHT,spaceAfter=15))
styles.add(ParagraphStyle(name='CoverTitle',fontName='Helvetica-Bold',fontSize=25,leading=31,textColor=NAVY,spaceAfter=15))
styles.add(ParagraphStyle(name='DeckTitle',fontName='Helvetica-Bold',fontSize=15,leading=21,textColor=NAVY,spaceBefore=14,spaceAfter=7,keepWithNext=True))
styles.add(ParagraphStyle(name='DeckSub',fontName='Helvetica-Bold',fontSize=11,leading=16,textColor=HIGHLIGHT,spaceBefore=10,spaceAfter=5,keepWithNext=True))
styles.add(ParagraphStyle(name='BodyE',fontName='Helvetica',fontSize=9.2,leading=14.5,textColor=NAVY,spaceAfter=8))
styles.add(ParagraphStyle(name='SmallE',fontName='Helvetica',fontSize=8,leading=12,textColor=MID,spaceAfter=5))
styles.add(ParagraphStyle(name='TableE',fontName='Helvetica',fontSize=7.3,leading=10.6,textColor=NAVY))
styles.add(ParagraphStyle(name='TableHeaderE',fontName='Helvetica-Bold',fontSize=7.3,leading=10.6,textColor=colors.white))
styles.add(ParagraphStyle(name='CallE',fontName='Helvetica-Bold',fontSize=9.5,leading=14,textColor=HIGHLIGHT,spaceAfter=10))
P=lambda s,sty='BodyE':Paragraph(escape(str(s)).replace('\n','<br/>'),styles[sty])
PB=lambda s,sty='BodyE':Paragraph(s,styles[sty])

REPORT=PUBLIC/'it113_final_report_draft.pdf'
def footer(c,doc):
    c.saveState();w,h=A4
    c.setStrokeColor(colors.HexColor('#E3DDEC'));c.line(19*mm,17.5*mm,w-19*mm,17.5*mm)
    c.setFont('Helvetica',7);c.setFillColor(MID)
    c.drawString(19*mm,12.5*mm,'FORTRESSAUTH  |  IT113 academic research  |  SYNTHETIC DATA ONLY')
    c.drawRightString(w-19*mm,12.5*mm,f'DRAFT  •  {doc.page}')
    c.restoreState()

def make_table(header, rows, widths, stripe=True):
    cell=lambda x,head=False: P(str(x),'TableHeaderE' if head else 'TableE')
    t=Table([[cell(x,True) for x in header]]+[[cell(x) for x in row] for row in rows],colWidths=widths,repeatRows=1,hAlign='LEFT')
    cmd=[('BACKGROUND',(0,0),(-1,0),HIGHLIGHT),('VALIGN',(0,0),(-1,-1),'TOP'),('LEFTPADDING',(0,0),(-1,-1),8),('RIGHTPADDING',(0,0),(-1,-1),8),('TOPPADDING',(0,0),(-1,-1),7),('BOTTOMPADDING',(0,0),(-1,-1),7),('LINEBELOW',(0,-1),(-1,-1),.5,colors.HexColor('#CFC5DC'))]
    if stripe:cmd.append(('ROWBACKGROUNDS',(0,1),(-1,-1),[colors.white,BG]))
    t.setStyle(TableStyle(cmd));return t

def heading(story,s):story.append(P(s,'DeckTitle'))
def sub(story,s):story.append(P(s,'DeckSub'))
def text(story,s):story.append(P(s))
def bullet(story,s):story.append(P('•  '+s))

story=[]
story.append(Spacer(1,24*mm))
story.append(P('IT113 | INFORMATION ASSURANCE AND SECURITY 2','CoverKicker'))
story.append(P('AI- and Machine Learning-Based Vulnerability Assessment and Threat Analysis System','CoverTitle'))
story.append(HRFlowable(width='100%',thickness=3,color=HIGHLIGHT,spaceAfter=16))
story.append(P('FortressAuth - Hybrid Intelligent Threat Detection','DeckTitle'))
story.append(P('FINAL PROJECT REPORT | RESEARCH DRAFT - COMPLETION REQUIRED','CallE'))
for item in ['Team / group: [ENTER VERIFIED GROUP NAME]','Authors: [ENTER EXACT GROUP MEMBER NAMES]','Course: IT113 - Information Assurance and Security 2','Instructor: [VERIFY FROM COURSE RECORD]','Data: controlled synthetic numeric security telemetry','Report prepared from saved model-summary and held-out evidence files']:
    story.append(P(item))
story.append(Spacer(1,15*mm))
story.append(P('Submission requirements: PDF due 15 December 2026, 12:00 noon. Final presentation 16 December 2026, 8:00 AM (as stated in the provided project specifications).','SmallE'))
story.append(P('IMPORTANT: Replace group placeholders, include hosted screenshots, complete the manual QA, verify exports, and proofread before submission. This draft does not assert a production vulnerability scan.','CallE'))
story.append(PageBreak())
heading(story,'Executive summary')
text(story,f"FortressAuth is an academic cybersecurity threat-analysis research system. It uses a supervised XGBoost multiclass classifier and a compact normal-only reconstruction model to analyze 20 numeric features across seven simulated behavior classes. The preserved study contains {D['training_rows']:,} training rows, {D['validation_rows']:,} validation rows, and {D['test_rows']:,} held-out test rows. The XGBoost test accuracy is {100*X['accuracy']:.2f}% and macro F1 is {100*X['macro_f1']:.2f}%. This reflects a generated, intentionally balanced dataset with limited synthetic distribution shift; it is not a real-world attack detection rate.")
text(story,'The public research workspace provides dataset and evaluation views, held-out validation examples, synthetic inference, threat findings, mitigation guidance, and exports. Curated public findings are designed for shared academic viewing; private numeric CSV tests are not published to everyone. Findings and recommendations are advisory and require authorized human verification.')
sub(story,'What this report demonstrates and what remains unverified')
story.append(make_table(['Evidence already saved','Remaining before final submission'],[
 ['Versioned dataset split, input features, and saved metrics','Hosted browser screenshots and reproducibility rerun'],
 ['13 selected held-out examples including classification errors','Verification that deployed latest patch behaves correctly'],
 ['Category-mapped defensive recommendations','Implementation-effectiveness testing in an authorized environment'],
 ['Report and presentation drafts','Group identity, academic formatting and final team review']
],[77*mm,93*mm]))
heading(story,'1. Background, objectives, and scope')
text(story,'The project aims to identify patterns relevant to security triage by analyzing numeric, privacy-preserving web and authentication behavior. Its objectives are to classify seven behavior categories, identify anomalies, interpret results against measured performance, and provide defensible remediation options consistent with cybersecurity practice.')
text(story,'This is a controlled educational experiment. No public analysis sample contains actual credentials, IP addresses, user identities, raw network messages, or confirmed real incidents. The system is not a production scanner, vulnerability exploitation framework, or automated account-enforcement engine.')
heading(story,'2. Dataset understanding and quality')
text(story,f"A deterministic generator produced {D['training_rows']+D['validation_rows']+D['test_rows']:,} samples across seven classes. Each split contains equal class counts. Recorded seeds: train {D['split_seeds']['train']}, validation {D['split_seeds']['validation']}, test {D['split_seeds']['test']}. Independent test examples are generated with a limited synthetic shift from the same family of generators.")
story.append(make_table(['Split','Rows','Per class','Purpose'],[
 ['Training',f"{D['training_rows']:,}",'5,000','Fit classifier, fit normal-only reconstruction model'],
 ['Validation',f"{D['validation_rows']:,}",'1,000','Calibrate anomaly cutoff on normal-class rows'],
 ['Held-out test',f"{D['test_rows']:,}",'1,500','Final evaluation; not used for training or calibration']
],[32*mm,28*mm,29*mm,81*mm]))
sub(story,'Engineered numeric feature inventory')
cols=[D['features'][i:i+10] for i in (0,10)]
story.append(make_table(['Feature group (first ten)','Feature group (remaining ten)'],[[a,b] for a,b in zip(*cols)],[85*mm,85*mm]))
text(story,'Recorded invariant checks include nested time-window and request-count consistency, numeric finiteness, ratios, and integer counters. The saved metadata reports zero violations for all three splits. These controls improve internal consistency but cannot prove real-world representativeness.')
heading(story,'3. Model methodology and reproducibility')
sub(story,'Supervised classifier')
text(story,'XGBoost learns a seven-class prediction from 20 simulated security features. Recorded training settings use 320 trees and maximum depth 5. The classifier predicts a behavior label and confidence. Its feature importance is global model metadata, not a faithful causal explanation for any one sample.')
sub(story,'Anomaly detector')
text(story,'An MLPRegressor-based encoder/decoder is trained to reconstruct normal-class features, with a recorded 16-8-4-8-16 shape. The anomaly threshold was calibrated from normal validation samples at their 99th-percentile reconstruction error, not on the test set. The saved threshold is '+f"{A['threshold_p99']:.6f}"+'.')
sub(story,'Illustrative hybrid score')
f=SUMMARY['risk_fusion'];text(story,f"The live workflow also combines deterministic rule risk ({f['rule_weight']:.0%}), classifier risk ({f['xgboost_weight']:.0%}), and anomaly risk ({f['autoencoder_weight']:.0%}). These weights are illustrative and not independently calibrated against real-world outcomes. The saved held-out example file does not include rule scores, so no fake per-example hybrid score is reported here.")
sub(story,'Reproduction environment')
text(story,f"Environment recorded with the study: Python {R['python']}, NumPy {R['numpy']}, scikit-learn {R['scikit_learn']}, XGBoost {R['xgboost']}, random state {R['random_state']}. Run the project-provided training scripts and unit tests in a controlled environment and verify hashes before comparing new artifacts.")
heading(story,'4. Held-out model evaluation')
story.append(make_table(['Metric','Recorded value','Interpretation'],[
 ['Accuracy',f"{100*X['accuracy']:.4f}%",'Correct seven-class predictions on 10,500 synthetic test rows'],
 ['Macro precision',f"{100*X['macro_precision']:.4f}%",'Mean precision over seven balanced categories'],
 ['Macro recall',f"{100*X['macro_recall']:.4f}%",'Mean recall over seven categories'],
 ['Macro F1',f"{100*X['macro_f1']:.4f}%",'Mean per-class F1'],
 ['Autoencoder anomaly recall',f"{100*A['holdout_anomaly_recall']:.4f}%",'Synthetic anomalous records detected'],
 ['Autoencoder normal FPR',f"{100*A['holdout_normal_false_positive_rate']:.4f}%",'Synthetic normal records incorrectly flagged']
],[49*mm,35*mm,86*mm]))
sub(story,'Per-class test performance')
story.append(make_table(['Class','Precision','Recall','F1','Support'],[[cl.replace('_',' ').title(),f"{100*X['classification_report'][cl]['precision']:.2f}%",f"{100*X['classification_report'][cl]['recall']:.2f}%",f"{100*X['classification_report'][cl]['f1-score']:.2f}%",str(X['classification_report'][cl]['support'])] for cl in D['classes']],[54*mm,30*mm,30*mm,30*mm,26*mm]))
conf=X['confusion_matrix'];errorpairs=sorted([(conf[i][j],D['classes'][i],D['classes'][j]) for i in range(7) for j in range(7) if i!=j and conf[i][j]],reverse=True)
incorrect=sum(sum(row)-row[i] for i,row in enumerate(conf))
sub(story,'Error analysis')
text(story,f"The saved confusion matrix contains {incorrect} errors among {D['test_rows']:,} test rows. The largest confusion pairs include: "+'; '.join(f"{a.replace('_',' ').title()} predicted as {b.replace('_',' ').title()} ({n})" for n,a,b in errorpairs[:4])+'. Recognizing false-positive and false-negative costs requires further scenario review.')
heading(story,'5. Vulnerability assessment case studies (Rubric A)')
text(story,'Selected precomputed test cases permit transparent cross-checking of a known synthetic label, the saved prediction, and observed numeric features. These observations are potential weaknesses to investigate, not confirmed vulnerabilities. The case set is selectively curated and not a representative sample of test accuracy.')
examples=EVIDENCE['examples'];selected=[]
for name in ['brute_force_correct','credential_stuffing_correct','web_attack_correct','session_abuse_correct']:
 t=next((c for c in examples if c['id']==name),None)
 if t:selected.append(t)
error=next((c for c in examples if not c.get('correct')),None)
if error:selected.append(error)
for c in selected:
 sub(story,f"Case {c['id']}")
 text(story,f"Synthetic true label: {c['true_label'].replace('_',' ')}. Saved prediction: {c['predicted_label'].replace('_',' ')}. Agreement: {'Yes' if c['correct'] else 'No, model misclassified this example'}. Confidence: {100*c['confidence']:.2f}%. Anomaly flag: {c['anomaly']}. This is model output, not evidence of exploited vulnerability.")
 obs=sorted(((k,v) for k,v in c['features'].items() if k in ['failed_logins_15m','failed_logins_5m','unique_usernames_15m','suspicious_requests_15m','scanner_events_15m','csrf_failures_15m','auth_rejections_15m','qr_failures_15m']), key=lambda x:-x[1])[:4]
 text(story,'Numeric indicators: '+', '.join(f'{k}={v:g}' for k,v in obs)+'. Cross-check: compare saved label/prediction and inspect authorized supporting records before assigning any real-world security impact.')
heading(story,'6. Mitigation strategies and security alignment (Rubric D)')
text(story,'Recommendations are proportional, scenario-based controls mapped to behavior classes. A category prediction alone cannot establish a successful attack. The analyst should confirm observed indicators, select an approved control, and verify the control using safe, authorized regression tests. NIST SP 800-61 Rev. 3 supports integrating incident response with wider risk management and organizational processes.')
mit=[
('Normal','Confirm stable baselines','Preserve proportionate telemetry; no automatic enforcement','Review false positives and legitimate access','OWASP logging / NIST response'),
('Brute force','Correlate repeated password failures','Per-account/source throttling; appropriate MFA','Test throttling without legitimate lockout','OWASP Authentication / MFA'),
('Credential stuffing','Correlate multi-account failure patterns','Account/source throttling; MFA and compromised-password protections','Test synthetic multi-account throttling','OWASP Authentication / MFA'),
('Reconnaissance','Review sensitive route probes','Restrict exposed administration; check authorization','Validate access controls on restricted routes','OWASP Authorization'),
('Web attack','Review suspicious/malformed requests','Parameterized SQL, contextual encoding, CSRF controls','Run authorized non-destructive regression tests','OWASP SQLi / XSS / CSRF'),
('MFA abuse','Review repeated second-factor attempts','Challenge expiry/binding and retry limits','Test controlled replay and expired challenges','OWASP MFA'),
('Session abuse','Review CSRF rejects and session anomalies','Rotate IDs, secure cookie configuration, CSRF defense','Test session lifecycle and CSRF rejection','OWASP Session / CSRF')]
for name,observe,action,verify,refs in mit:
 sub(story,name)
 text(story,'Observe: '+observe+'. Respond: '+action+'. Confirm effectiveness: '+verify+'. Guidance: '+refs+'.')
text(story,'The separate Threat Mitigations interface includes full, category-specific control matrices, verification steps, and links to the primary OWASP and NIST references. Selected findings can be linked to the corresponding class plan. No automatic blocking is initiated by the academic dashboard.')
heading(story,'7. Discussion, strengths, limitations and ethics')
sub(story,'Strengths')
for s in ['Deterministic synthetic generation and separate training, validation and held-out test roles.','Seven-category evaluation with per-class precision, recall, F1, confusion matrix and error examples.','Explicit control-mapping and verification steps, without presenting anomaly scores as proven vulnerabilities.','Public curated research separated from private numeric CSV samples and administrative operations.']:
 bullet(story,s)
sub(story,'Limitations')
for s in ['Class-balanced simulated inputs do not match actual incident prevalence, cost or adversary behavior.','Synthetic distribution shift is not an externally collected real-world test set.','Unusually strong anomaly metrics reflect the data generator and should not be generalized.','Neither threshold flags nor global feature importance establish sample-level causality.','Risk fusion weights and recommended controls lack independently measured field effectiveness.','Live hosting, cross-device persistence, private export security, and visual regression require separate verification.']:
 bullet(story,s)
sub(story,'Academic and ethical compliance')
text(story,'Use only authorized controlled synthetic inputs. Do not submit credentials, personal identifiers, real raw logs, live attack traffic, tokens, Supabase configuration, or private administrative records. Recommendations are advisory; security decisions and deployments need an authorized human reviewer. This report makes no claim of successful exploitation or proven remediation.')
heading(story,'8. Final verification and evidence to attach')
checks=['Run all seven curated classifications and record model version, trace, label, risk and indicators.','Confirm public curated results persist on refresh and appear in another browser after bounded polling.','Check numeric CSV import using valid synthetic data, plus a rejection case for nonnumeric values.','Select a stored finding; verify its category-specific control plan and export JSON.','Verify report and presentation downloads, report print/PDF formatting, and redaction safety.','Check browser console, mobile responsiveness, rates, database availability and failure recovery.','Attach hosted screenshots for Dataset Assessment, Evaluation, AI Defense, Threat Mitigations, Reports and validation examples.','Complete group names, cite technical references, verify instructor naming convention and review ethics.']
for s in checks:bullet(story,'[  ] '+s)
text(story,'Important: unverified checklist items remain pending; a file download or code review alone is not an end-to-end test.')
heading(story,'9. References and source provenance')
refs=[
('NIST','Incident Response Recommendations and Considerations for Cybersecurity Risk Management: A CSF 2.0 Community Profile (SP 800-61 Rev. 3, April 2025)','https://csrc.nist.gov/pubs/sp/800/61/r3/final'),
('OWASP','Authentication Cheat Sheet','https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html'),
('OWASP','Multifactor Authentication Cheat Sheet','https://cheatsheetseries.owasp.org/cheatsheets/Multifactor_Authentication_Cheat_Sheet.html'),
('OWASP','SQL Injection Prevention Cheat Sheet','https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html'),
('OWASP','Cross Site Scripting Prevention Cheat Sheet','https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html'),
('OWASP','Cross-Site Request Forgery Prevention Cheat Sheet','https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html'),
('OWASP','Session Management Cheat Sheet','https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html'),
('OWASP','Authorization Cheat Sheet','https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html'),
('OWASP','Logging Cheat Sheet','https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html'),
('Project','model_summary.json, evidence.json, training source and Phase 1 evaluation notes','Bundled FortressAuth IT113 project artifacts'),
('Instructor','IT113 Final Term Project Specifications','Course-supplied three-page project requirements and grading rubric')]
for source,desc,url in refs:story.append(P(f'{source}: {desc}. {url}','SmallE'))
story.append(PageBreak())
heading(story,'Appendix: documentation status and sign-off')
text(story,'[  ] Confirm team/course identifiers  [  ] Add actual hosted screenshots  [  ] Verify stored metrics with a reproducibility run  [  ] Test current deployment  [  ] Final team approval  [  ] Submit correctly named PDF')
sub(story,'Required final screenshot evidence')
story.append(make_table(['Capture','What must be visible'],[
 ['Dataset Assessment','Study split, feature interpretation and rubric A case evidence'],
 ['Model Evaluation','Measured accuracy, macro-F1, confusion matrix and limitations'],
 ['AI Defense','Held-out synthetic prediction, supporting numeric indicators and model version'],
 ['Threat Findings','Selected case, status and evidence-to-control guidance'],
 ['Threat Mitigations','Category filter, practical response plan, OWASP/NIST sources and verification steps'],
 ['Research Reports','Evidence metrics, methodology panel and working export links']
],[57*mm,113*mm]))
sub(story,'Team review and sign-off')
text(story,'Author/Reviewer: ______________________    Reviewed date: ________________')
text(story,'Latest hosted URL: _______________________    Test devices: ________________')
text(story,'Final declared limitation: This study validates measured synthetic inference only. Deployment claims require documented hosted QA.')
text(story,'This report is intentionally a source-grounded working draft: instructor submission is not represented as finished until all sign-offs are complete.')
SimpleDocTemplate(str(REPORT),pagesize=A4,topMargin=20*mm,bottomMargin=22*mm,leftMargin=20*mm,rightMargin=20*mm,author='FortressAuth IT113 project team - DRAFT',title='FortressAuth IT113 Final Report - DRAFT').build(story,onFirstPage=footer,onLaterPages=footer)

# Editable student presentation - no source image or personal data required.
prs=Presentation();prs.slide_width=Inches(13.333);prs.slide_height=Inches(7.5)
PURPLE=RGBColor(153,115,219);WHITE=RGBColor(247,244,254);GRAY=RGBColor(182,172,202);DARK=RGBColor(19,16,33);CARD=RGBColor(36,28,58);TEAL=RGBColor(137,222,197)

def textbox(slide,text,left,top,width,height,size=18,bold=False,color=WHITE):
    shape=slide.shapes.add_textbox(Inches(left), Inches(top), Inches(width), Inches(height));tf=shape.text_frame;tf.word_wrap=True;tf.margin_left=tf.margin_right=Inches(.06);tf.margin_top=Inches(.02)
    p=tf.paragraphs[0];p.text=str(text);p.font.size=Pt(size);p.font.bold=bold;p.font.name='Aptos';p.font.color.rgb=color;return shape

def slide(title,kicker='IT113 | FINAL PROJECT',notes=None):
    s=prs.slides.add_slide(prs.slide_layouts[6]); bg=s.background.fill;bg.solid();bg.fore_color.rgb=DARK
    # left accent line
    shape=s.shapes.add_shape(MSO_SHAPE.RECTANGLE, Inches(.65),Inches(.65),Inches(.075),Inches(.65));shape.fill.solid();shape.fill.fore_color.rgb=PURPLE;shape.line.fill.background()
    textbox(s,kicker,.86,.43,11,.25,10,True,TEAL)
    textbox(s,title,.87,.84,11.4,.78,28,True)
    textbox(s,'FORTRESSAUTH  /  SYNTHETIC RESEARCH  /  DRAFT',.85,7.12,10,.22,10,False,GRAY)
    if notes:s.notes_slide.notes_text_frame.text=notes
    return s

def block(s,title,lines,x,y,w,h):
    sh=s.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE,Inches(x),Inches(y),Inches(w),Inches(h));sh.fill.solid();sh.fill.fore_color.rgb=CARD;sh.line.color.rgb=RGBColor(66,49,91)
    textbox(s,title,x+.22,y+.16,w-.4,.40,17,True,PURPLE)
    text='\n'.join('• '+str(line) for line in lines)
    textbox(s,text,x+.22,y+.68,w-.45,h-.8,18,False,WHITE)

def bulletslide(title,rows,kicker='METHODOLOGY'):
    s=slide(title,kicker);block(s,'Key evidence',rows,.84,1.85,11.6,4.95);return s

s=slide('AI- and ML-Based Threat Analysis','FORTRESSAUTH | IT113 FINAL PROJECT',notes='Presenter: enter exact names and provide screenshots from the final hosted release.')
textbox(s,'Hybrid Intelligent Threat Detection',.9,2.0,11.0,.66,29,True,PURPLE)
textbox(s,'XGBoost + normal-only autoencoder + interpretable rule signals',.9,3.08,11.0,.6,21)
textbox(s,'GROUP: [ENTER NAMES]     •     ACADEMIC SYNTHETIC STUDY',.9,5.38,11.1,.4,15,False,TEAL)
bulletslide('Problem statement and objectives',['Classify suspicious behavior patterns rather than confirmed attacks','Evaluate how consistently trained models recognize known synthetic threat categories','Interpret false positives and false negatives before acting','Recommend proportionate, evidence-based defensive controls'],'PROJECT CONTEXT')
s=slide('System workflow','TECHNICAL ARCHITECTURE')
for i,(tit,desc) in enumerate([('Input','20 numeric synthetic features'),('Classifier','7-class XGBoost prediction'),('Anomaly','Normal-only reconstruction model'),('Risk & rules','Illustrative weighted risk and threshold flags'),('Analyst review','Category-specific guidance and status')]):
    x=.76+i*2.55
    sh=s.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE,Inches(x),Inches(2.18),Inches(2.30),Inches(2.68));sh.fill.solid();sh.fill.fore_color.rgb=CARD;sh.line.color.rgb=PURPLE
    textbox(s,tit,x+.17,2.45,2.0,.42,17,True,PURPLE);textbox(s,desc,x+.17,3.17,2.02,1.29,15)
    if i<4:textbox(s,'→',x+2.25,3.12,.36,.4,23,True,TEAL)
textbox(s,'No automatically confirmed vulnerabilities or user sanctions',.9,5.42,11.4,.48,17,False,TEAL)
s=slide('Dataset and evaluation protocol','RUBRIC A + B')
for i,(t,n,txt) in enumerate([('TRAIN',D['training_rows'],'Fit classifier + reconstruction model'),('VALIDATION',D['validation_rows'],'Calibrate anomaly threshold'),('TEST',D['test_rows'],'Held-out metrics')]):
    x=.85+i*4.23;block(s,t,[f'{n:,} simulated records',txt],x,2.1,3.95,3.5)
textbox(s,'7 balanced behavior categories  •  20 numeric features  •  deterministic seeds',1,6.10,11.5,.5,17,False,TEAL)
bulletslide('Seven synthetic behavior categories',[x.replace('_',' ').title() for x in D['classes']],'DATASET TAXONOMY')
s=slide('Held-out model performance','RUBRIC C')
for i,(lbl,value) in enumerate([('Accuracy',f"{100*X['accuracy']:.2f}%"),('Macro F1',f"{100*X['macro_f1']:.2f}%"),('AE anomaly recall',f"{100*A['holdout_anomaly_recall']:.2f}%"),('AE normal FPR',f"{100*A['holdout_normal_false_positive_rate']:.2f}%")]):
    x=.85+(i%2)*6.0;y=1.95+(i//2)*2.20;block(s,lbl,[value],x,y,5.65,1.92)
textbox(s,'Synthetic held-out split; NOT validated real-world incident accuracy',.85,6.62,11.5,.38,15,False,TEAL)
bulletslide('Model errors and interpretation',[f'{incorrect} total misclassifications among 10,500 test samples',f"Largest confusion: {errorpairs[0][1].replace('_',' ').title()} → {errorpairs[0][2].replace('_',' ').title()} ({errorpairs[0][0]} records)",'Model confidence does not imply certainty or a confirmed security incident','Inspect selected saved incorrect examples and numeric features'],'RUBRIC A + C')
bulletslide('Evidence-based case study workflow',['Choose a saved held-out case in Dataset Assessment','Compare synthetic true label and model prediction','Review actual numeric indicators and consistency checks','Record an honest match/mismatch and investigate potential weaknesses','Export the selected case study as JSON'],'RUBRIC A')
bulletslide('Mitigation plan: evidence → control → verification',['Confirm observed values and inspect authorized, sanitized records','Select category-relevant protections and accountable review','Compare changes against an approved secure baseline','Retest with harmless controlled inputs; monitor false positives','Avoid automatic bans or unverified vulnerability claims'],'RUBRIC D')
s=slide('Seven-category mitigation coverage','RUBRIC D')
block(s,'Authentication',['Brute force: throttling + MFA','Credential stuffing: account/source throttling','MFA abuse: challenge expiry and retry limits'],.85,1.92,5.62,3.75)
block(s,'Application and sessions',['Reconnaissance: authorization review','Web attack: parameterization and output encoding','Session abuse: session ID rotation + CSRF','Normal: baseline monitoring only'],6.73,1.92,5.62,3.75)
textbox(s,'Aligned to OWASP Cheat Sheet guidance and NIST SP 800-61 Rev. 3',.85,6.28,11.4,.42,15,False,TEAL)
bulletslide('Academic and ethical limits',['Synthetic balanced data is not operational attack telemetry','No real user/IP/credential/log data required for public assessment','Saved anomaly metrics may be inflated by synthetic separation','Illustrative fusion weights not independently field-calibrated','Analysts must validate threats and mitigations before action'],'RUBRIC E')
bulletslide('Verification still required before submission',['Add group names, final instructor-facing citations and exact filename','Capture screenshots of latest hosted deployment on desktop/mobile','Test seven categories, CSV validation, two-visitor persistence and downloads','Confirm D plan links, Threat Finding selection and status workflow','Recheck evidence accuracy and presentation narration'],'FINAL QA')
s=slide('Conclusions and next steps','IT113 FINAL PROJECT')
block(s,'What is demonstrated',[f'XGBoost: {100*X["accuracy"]:.2f}% held-out synthetic test accuracy','Seven-class behavior analysis and normal-only anomalies','Case-level evidence and OWASP/NIST-aligned mitigations'],.85,1.95,5.62,4.1)
block(s,'Before delivery',['Validate hosted update and regression workflows','Add final screenshots and team identifiers','Review PDF, presentation and ethics statements','Do not present synthetic tests as field accuracy'],6.72,1.95,5.62,4.1)
s=slide('Source references and project provenance','ACADEMIC REFERENCES')
block(s,'Official security references',['NIST SP 800-61 Rev. 3 (April 2025)','OWASP Authentication + MFA Cheat Sheets','OWASP SQL Injection, XSS and CSRF Prevention','OWASP Session Management + Authorization'],.85,1.92,5.63,4.2)
block(s,'Saved project evidence',['model_summary.json (20 features + metrics)','evidence.json (selected synthetic held-out cases)','Project training and tests (reproducibility)','IT113 Final Term Project Specifications'],6.73,1.92,5.63,4.2)
textbox(s,'Report includes clickable reference URLs and full research limitations',.86,6.45,11.7,.45,16,False,TEAL)
PPT=PUBLIC/'it113_final_presentation_draft.pptx';prs.save(str(PPT))
print('REPORT',REPORT,REPORT.stat().st_size)
print('PRESENTATION',PPT,PPT.stat().st_size)
