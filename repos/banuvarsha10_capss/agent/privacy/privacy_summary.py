import os
import csv
import re


# --------------------------------------------------
# File Paths
# --------------------------------------------------

BASE_DIR = os.path.dirname(os.path.abspath(__file__))


DATASET_DIR = os.path.join(
    BASE_DIR,
    "..",
    "datasets"
)


RESULTS_DIR = os.path.join(
    BASE_DIR,
    "..",
    "results"
)


os.makedirs(
    RESULTS_DIR,
    exist_ok=True
)



ANON_DATASET = os.path.join(
    RESULTS_DIR,
    "anonymized_registration_dataset4.csv"
)



PRIVACY_REPORT = os.path.join(
    RESULTS_DIR,
    "privacy_report.txt"
)



CORRELATION_REPORT = os.path.join(
    RESULTS_DIR,
    "correlation_report.txt"
)



THREAT_REPORT = os.path.join(
    RESULTS_DIR,
    "privacy_threat_report.txt"
)



SECURITY_CONTEXT = os.path.join(
    RESULTS_DIR,
    "privacy_test.csv"
)



OUTPUT_FILE = os.path.join(
    RESULTS_DIR,
    "privacy_summary.txt"
)





# --------------------------------------------------
# Read Existing Reports
# --------------------------------------------------

def read_file(path):

    if os.path.exists(path):

        with open(
            path,
            "r",
            encoding="utf-8"
        ) as file:

            return file.read()

    return "Report not available."




privacy_report = read_file(
    PRIVACY_REPORT
)


correlation_report = read_file(
    CORRELATION_REPORT
)


threat_report = read_file(
    THREAT_REPORT
)





# --------------------------------------------------
# Extract Privacy Metrics
# --------------------------------------------------

def extract_value(text, keyword):

    pattern = keyword + r".*?:\s*(.*)"

    match = re.search(
        pattern,
        text
    )

    if match:

        return match.group(1).strip()

    return "Not available"





privacy_score = extract_value(
    privacy_report,
    "Average Privacy Score"
)


# NOTE: was previously extract_value(privacy_report, "Exposure Score"),
# which is a substring of BOTH "Highest Exposure Score" and
# "Lowest Exposure Score" - re.search silently grabbed whichever
# line came first (Highest), while the summary label below called
# it "Average Exposure Score". There is no "Average Exposure Score"
# line in privacy_report.txt, so the label was simply wrong about
# what the number represented. Targeting the exact label removes
# the ambiguity.
exposure_score = extract_value(
    privacy_report,
    "Highest Exposure Score"
)


# --------------------------------------------------
# Extract Privacy Risk Score (Step 3, from privacy_score.py)
# --------------------------------------------------

average_risk_score = extract_value(
    privacy_report,
    "Average Overall Risk Score"
)


highest_risk_score = extract_value(
    privacy_report,
    "Highest Overall Risk Score"
)


lowest_risk_score = extract_value(
    privacy_report,
    "Lowest Overall Risk Score"
)


risk_level = extract_value(
    privacy_report,
    "Overall Risk Level"
)






# --------------------------------------------------
# Security Context Summary (Step 4/5, from security_context.py)
# --------------------------------------------------
# NOTE: This standalone section used to always print "Security
# context unavailable" in practice (privacy4.csv typically isn't
# present), while the exact same attack-event information is
# already covered in full by the correlation report's "SECURITY
# CONTEXT ANALYSIS" section and the threat report's attack
# sections further down. Printing an "unavailable" placeholder
# between two sections that DO have the data added noise without
# adding information, so this section is now only included in the
# final summary when privacy4.csv is actually present and has
# attacks in it - see the build step below.

def extract_attack_summary():

    if not os.path.exists(SECURITY_CONTEXT):

        return None


    with open(
        SECURITY_CONTEXT,
        "r",
        encoding="utf-8"
    ) as file:

        reader = csv.DictReader(file)

        attacks = []

        for row in reader:

            if row.get("Attack_Detected") == "True":

                attacks.append(
                    {
                    "Type": row.get("Attack_Type"),
                    "Severity": row.get("Severity"),
                    "Confidence": row.get("Confidence"),
                    "Decision": row.get("Decision")
                    }
                )


    if not attacks:

        return None


    return attacks




attack_summary = extract_attack_summary()



def format_security_context(attacks):

    if not attacks:

        return None


    lines = []

    for attack in attacks:

        lines.append(
            f"{attack.get('Type')} — Severity: {attack.get('Severity')}, "
            f"Confidence: {attack.get('Confidence')}, Decision: {attack.get('Decision')}"
        )

    return "\n".join(lines)




security_context_text = format_security_context(attack_summary)





# --------------------------------------------------
# De-duplicate the Threat Report Against the Correlation Report
# --------------------------------------------------
# The threat report's "SECTION B — CONFIRMED ATTACKS" lists every
# single attack event as its own block (UE ID / Attack / Decision /
# Severity / Confidence) - one block per request. That is the same
# event-level data already shown, request-by-request, in the
# correlation report's "PER-UE SECURITY BREAKDOWN" and "BEHAVIOUR
# TIMELINE" sections, which appear earlier in this same summary.
#
# Rather than print all N rows twice, Section B is collapsed here
# into one line per (UE, attack type, decision, severity) with a
# count and average confidence, and a pointer back to the
# correlation section for the full chronological detail. No
# information is dropped - it's stated once instead of twice.

def collapse_confirmed_attacks(text):

    section_match = re.search(
        r"SECTION B — CONFIRMED ATTACKS.*?\n-{5,}\n(.*?)\n-{5,}\nSECTION C",
        text,
        re.DOTALL
    )

    if not section_match:
        return text

    block = section_match.group(1)

    entries = re.findall(
        r"UE ID\s*:\s*(.+?)\n"
        r"Confirmed Attack\s*:\s*(.+?)\n"
        r"Decision\s*:\s*(.+?)\n"
        r"Severity\s*:\s*(.+?)\n"
        r"Confidence\s*:\s*(\d+)%",
        block
    )

    if not entries:
        return text

    tally = {}
    order = []

    for ue_id, attack_type, decision, severity, confidence in entries:

        key = (ue_id.strip(), attack_type.strip(), decision.strip(), severity.strip())

        if key not in tally:
            tally[key] = {"count": 0, "confidence_total": 0}
            order.append(key)

        tally[key]["count"] += 1
        tally[key]["confidence_total"] += int(confidence)

    collapsed_lines = [
        "(Event-by-event detail already appears above in the Correlation "
        "Analysis section - see PER-UE SECURITY BREAKDOWN / BEHAVIOUR "
        "TIMELINE. This is the deduplicated tally by UE and attack type.)\n"
    ]

    for key in order:

        ue_id, attack_type, decision, severity = key
        stats = tally[key]
        avg_conf = stats["confidence_total"] / stats["count"]

        collapsed_lines.append(
            f"{ue_id} — {attack_type} x{stats['count']} "
            f"(Decision: {decision}, Severity: {severity}, "
            f"Avg Confidence: {avg_conf:.0f}%)"
        )

    replacement = (
        "SECTION B — CONFIRMED ATTACKS (deduplicated)\n"
        "---------------------------------------------------------\n\n"
        + "\n".join(collapsed_lines) + "\n\n"
        "---------------------------------------------------------\nSECTION C"
    )

    return (
        text[:section_match.start()]
        + replacement
        + text[section_match.end():]
    )


threat_report = collapse_confirmed_attacks(threat_report)





# --------------------------------------------------
# Metadata Minimization Verification
# --------------------------------------------------

def check_minimization():


    result = {}


    if not os.path.exists(ANON_DATASET):

        return {

            "Dataset": "Missing"

        }



    with open(
        ANON_DATASET,
        "r",
        encoding="utf-8"
    ) as file:


        reader = csv.DictReader(file)


        rows = list(reader)



    if len(rows) == 0:

        return {

            "Dataset": "Empty"

        }



    sample = rows[0]



    # UE ID check
    # Handles plain pseudonyms (UE_001) as well as future hashed
    # values (e.g. "9a34e67fa...") which won't start with "UE_"
    # but will still be long, opaque identifiers.

    ue = sample.get(
        "UE_ID",
        ""
    )


    if (
        ue.startswith("UE_")
        or
        len(ue) > 10
    ):

        result["UE_ID"] = "✓ Pseudonymized"

    else:

        result["UE_ID"] = "✗ Not Pseudonymized"




    # SUCI check

    suci = sample.get(
        "SUCI",
        ""
    )


    if (
        "SUCI" in suci
        and
        suci.replace(
            "SUCI_",
            ""
        ).isdigit()
    ):

        result["SUCI"] = "✓ Pseudonymized"

    else:

        result["SUCI"] = "✗ Not Pseudonymized"





    # gNB IP check

    gnb = sample.get(
        "gNB_IP",
        ""
    )


    if (
        "xxx" in gnb
        or
        "*" in gnb
    ):

        result["gNB_IP"] = "✓ Masked"

    else:

        result["gNB_IP"] = "✗ Exposed"





    # Timestamp check

    timestamp = sample.get(
        "Timestamp",
        ""
    )


    if (
        ":" not in timestamp
        or
        len(timestamp)<15
    ):

        result["Timestamp"] = "✓ Generalized"

    else:

        result["Timestamp"] = "✗ Exact Timestamp"





    # DNN

    dnn = sample.get(
        "DNN",
        ""
    )


    if (
        dnn.lower()
        in
        [
            "generic",
            "masked",
            "unknown",
            "default_dnn"
        ]

    ):

        result["DNN"] = "✓ Generalized"

    else:

        result["DNN"] = "✗ Original"



    # S-NSSAI

    snssai = sample.get(
        "S_NSSAI",
        ""
    )


    if (
        "masked" in snssai.lower()
        or
        "generic" in snssai.lower()
        or
        "default" in snssai.lower()
    ):

        result["S_NSSAI"] = "✓ Generalized"

    else:

        result["S_NSSAI"] = "✗ Original"



    return result






minimization = check_minimization()




# --------------------------------------------------
# Duplicate Record Verification
# --------------------------------------------------

def check_duplicates():

    if not os.path.exists(ANON_DATASET):

        return "Not available"


    with open(
        ANON_DATASET,
        "r",
        encoding="utf-8"
    ) as file:

        rows = list(csv.DictReader(file))


    total = len(rows)

    unique = len(
        set(
            tuple(r.items())
            for r in rows
        )
    )


    removed = total - unique


    return removed




duplicates_removed = check_duplicates()





# --------------------------------------------------
# Build Summary
# --------------------------------------------------

security_context_section = ""

if security_context_text:

    security_context_section = f"""

========================================================

SECURITY CONTEXT SUMMARY

--------------------------------------------------------

Source:
security_context.py


{security_context_text}


"""


summary = f"""

========================================================
             CAPSS PRIVACY SUMMARY REPORT
========================================================


PRIVACY SCORE ANALYSIS
--------------------------------------------------------

Source:
privacy_score.py


Average Privacy Score:

{privacy_score}


Highest Exposure Score:

{exposure_score}








========================================================

PRIVACY RISK SCORE

--------------------------------------------------------

Source:
privacy_score.py


Average Risk Score:

{average_risk_score}


Highest Risk Score:

{highest_risk_score}


Lowest Risk Score:

{lowest_risk_score}


Overall Risk Level:

{risk_level}
{security_context_section}







========================================================

METADATA MINIMIZATION VERIFICATION

--------------------------------------------------------

Source:
anonymized_registration_dataset.csv


UE IDs:

{minimization.get("UE_ID")}


SUCIs:

{minimization.get("SUCI")}


gNB IP Address:

{minimization.get("gNB_IP")}


Timestamp:

{minimization.get("Timestamp")}


DNN:

{minimization.get("DNN")}


S-NSSAI:

{minimization.get("S_NSSAI")}


Duplicate Records Removed:

{duplicates_removed}






========================================================

CORRELATION ANALYSIS

--------------------------------------------------------

Source:
correlation_analyzer.py


{correlation_report}






========================================================

THREAT ANALYSIS

--------------------------------------------------------

Source:
privacy_threat_analyzer.py


{threat_report}





========================================================

FINAL CAPSS PRIVACY OBSERVATION

--------------------------------------------------------

• Privacy score is obtained from the dedicated
  privacy scoring module.


• Metadata minimization status is verified
  directly from anonymized dataset.


• Correlation information is obtained from
  correlation analyzer output.


• Threat intelligence is obtained from the security
  context generated by the protection layer.


• Privacy risk combines metadata exposure,
  behavioural correlation and external threat
  severity information.


• CAPSS combines privacy, correlation and
  threat intelligence to generate final
  privacy assessment.



========================================================

"""




# --------------------------------------------------
# Display
# --------------------------------------------------

print(summary)




# --------------------------------------------------
# Save Report
# --------------------------------------------------

with open(
    OUTPUT_FILE,
    "w",
    encoding="utf-8"
) as file:

    file.write(summary)



print(
    "Privacy Summary generated successfully!"
)

print(
    OUTPUT_FILE
)