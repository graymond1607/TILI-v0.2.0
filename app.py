from pathlib import Path
import sys
import time
import re
from collections import Counter

import pandas as pd
import plotly.express as px
import streamlit as st

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "src"))

from tili.ingestion import read_uploaded_files
from tili.analyzer import analyse_documents
from tili.reporting import findings_dataframe, report_json
from tili.parsing import parse_lines
from tili.correlation import build_instance_comparison
from tili.inventory.certificate_monitor import extract_card_validity
from tili.settings import load_settings
from tili.i18n import translate

settings = load_settings()
APP_VERSION = settings.get("app", {}).get("version", "0.2.0")
LOGO_PATH = Path.home() / ".local/share/icons/TILI_v0.2_icon.png"

st.set_page_config(
    page_title="TILI - TI Log Intelligence",
    page_icon=str(LOGO_PATH),
    layout="wide"

)

language_choice = st.sidebar.selectbox(
    "Language / Sprache",
    ["English", "Deutsch"],
    index=0,
    key="language_choice"
)

language = "de" if language_choice == "Deutsch" else "en"

def t(key):
    return translate(key, language)


logo_col, title_col = st.columns([0.12, 0.88])

with logo_col:
    if LOGO_PATH.exists():
        st.image(str(LOGO_PATH), width=90)

with title_col:
    st.title("TI Log Intelligence")
    st.caption(f"TILI v{APP_VERSION} · " + t("app_subtitle"))
    st.caption(t("supported_systems"))

with st.sidebar:
    st.header(t("analysis_settings"))

    if st.button(t("reset"), type="secondary", use_container_width=True):
        st.session_state["uploader_version"] = (
            st.session_state.get("uploader_version", 0) + 1
        )
        st.session_state["use_sample"] = False
        st.rerun()

    window = st.slider(t("correlation_window"), 1, 60, 10)

    st.divider()
    st.markdown(f"**{t('supported_uploads')}**")
    st.caption("LOG · TXT · CSV · JSON · ZIP")
    st.info(t("privacy"))

uploaded = st.file_uploader(
    t("upload"),
    type=["log", "txt", "csv", "json", "zip"],
    accept_multiple_files=True,
    key=f"log_uploader_{st.session_state.get('uploader_version', 0)}",
)

sample_path = ROOT / "data" / "samples" / "sample_mixed.log"
use_sample = st.checkbox(
    t("sample"),
    value=False,
    key="use_sample",
)

documents = []
if uploaded:
    try:
        documents = read_uploaded_files(uploaded)
    except Exception as exc:
        st.error(f"Upload error: {exc}")

if use_sample and not uploaded:
    documents = [(sample_path.name, sample_path.read_text(encoding="utf-8"))]

st.write("DEBUG — Uploaded files:", len(uploaded) if uploaded else 0, "| Documents returned:", len(documents))

if not documents:
    st.info("Upload one or more log files, or select the synthetic sample to explore the prototype.")
    st.stop()

# Temporary timestamp-format diagnostics
timestamp_stats = {
    "ISO timestamps": 0,
    "German timestamps": 0,
    "ISO with timezone": 0,
    "Lines without recognised timestamp": 0,
}

for filename, text in documents:
    for line in text.splitlines():
        iso_match = re.search(
            r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}",
            line,
        )
        german_match = re.search(
            r"\d{2}\.\d{2}\.\d{4}[ ,T]+\d{2}:\d{2}:\d{2}",
            line,
        )

        if iso_match:
            timestamp_stats["ISO timestamps"] += 1

            if re.search(r"(?:Z|[+-]\d{2}:?\d{2})\b", line):
                timestamp_stats["ISO with timezone"] += 1

        elif german_match:
            timestamp_stats["German timestamps"] += 1
        else:
            timestamp_stats["Lines without recognised timestamp"] += 1

st.write("DEBUG — Timestamp formats:", timestamp_stats)

# Parse each document once for unified analysis.
parse_start = time.perf_counter()
parsed_documents = []

for filename, text in documents:
    events = parse_lines(text, filename)
    parsed_documents.append((filename, events))

parse_duration = time.perf_counter() - parse_start
parsed_event_count = sum(len(events) for _, events in parsed_documents)

st.write(
    f"DEBUG — Parsing: {parse_duration:.2f} seconds | "
    f"Events: {parsed_event_count:,}"
)


try:
    result = analyse_documents(
        documents,
        correlation_window_minutes=window,
        parsed_documents=parsed_documents,
    )

except Exception as exc:
    st.exception(exc)
    st.stop()

# Performance diagnostics
st.subheader("Performance Diagnostics")

timings = result.get("timings", {})

performance_data = {
    "Parsing": parse_duration,
    "Finding detection": timings.get("finding_detection", 0),
    "Instance comparison": timings.get("instance_comparison", 0),
    "Root-cause hypotheses": timings.get("root_cause_hypotheses", 0),
    "Identifier inventory": timings.get("identifier_inventory", 0),
    "Correlation": timings.get("correlation", 0),
    "Error frequency": timings.get("error_frequency", 0),
}

for stage, duration in performance_data.items():
    st.write(f"**{stage}:** {duration:.3f} seconds")

summary = result["summary"]
m1, m2, m3, m4, m5 = st.columns(5)
m1.metric(t("files"), summary["files"])
m2.metric(t("events"), summary["events"])
m3.metric(t("findings"), summary["findings"])
m4.metric(t("high"), summary["high"])
m5.metric(t("correlated"), len(result["correlations"]))
instance_rows = result.get("instances", [])

identified_devices = len({
    row["identity_id"]
    for row in instance_rows
    if row.get("identity_id")
})

unidentified_entries = sum(
    1 for row in instance_rows
    if not row.get("identity_id")
)

m6, m7 = st.columns(2)
m6.metric(t("identified_devices"), identified_devices)
m7.metric(t("unidentified_entries"), unidentified_entries)

tab_overview, tab_findings, tab_timeline, tab_correlation, tab_inventory, tab_ai, tab_export = st.tabs([
    t("overview"),
    t("findings"),
    t("timeline"),
    t("correlations"),
    t("inventory"),
    t("ai"),
    t("export")
])

with tab_overview:
    st.subheader(t("source_distribution"))
    source_data = pd.DataFrame(
        [
            {
                t("source"): key,
                t("chart_events"): value
            }
            for key, value in summary["sources"].items()
        ]
    )

    if not source_data.empty:
        st.plotly_chart(
            px.bar(
                source_data,
                x=t("source"),
                y=t("chart_events"),
                title=t("parsed_events_source")
            ),
            use_container_width=True
        )
    else:
        st.warning(t("no_events"))

    st.subheader(t("severity_distribution"))
    fdf = findings_dataframe(result["findings"])

    if not fdf.empty:
        sev = (
            fdf.groupby("severity")
            .size()
            .reindex(["HIGH", "MEDIUM", "LOW"], fill_value=0)
            .rename("count")
            .reset_index()
        )

        sev["severity_label"] = sev["severity"].map({
            "HIGH": t("high_category"),
            "MEDIUM": t("medium_category"),
            "LOW": t("low_category")
        })

        fig = px.bar(
            sev,
            x="severity_label",
            y="count",
            title=t("detected_by_severity"),
            labels={
                "severity_label": t("severity"),
                "count": t("count")
            },
            category_orders={
                "severity_label": [
                    t("high_category"),
                    t("medium_category"),
                    t("low_category")
                ]
            }
        )

        st.plotly_chart(fig, use_container_width=True)
    else:
        st.success(t("no_rules_matched"))

with tab_findings:
    st.subheader(t("detected_findings"))
    st.error(t("red_error"))
    fdf = findings_dataframe(result["findings"])
    if fdf.empty:
        st.info(t("no_findings"))
    else:
        filters = st.columns(3)
        all_option = t("all")
        sources = [all_option] + sorted(fdf["source"].unique().tolist())
        severities = [all_option] + sorted(fdf["severity"].unique().tolist())
        selected_source = filters[0].selectbox(t("source"), sources)
        selected_severity = filters[1].selectbox(t("severity"), severities)
        search_text = filters[2].text_input(t("search"))
        view = fdf.copy()
        if selected_source != all_option:
            view = view[view["source"] == selected_source]
        if selected_severity != all_option:
            view = view[view["severity"] == selected_severity]
        
        if search_text:
            view = view[view.astype(str).apply(
                lambda col: col.str.contains(search_text, case=False, na=False)
            ).any(axis=1)]

        column_translations = {
            "source": t("source"),
            "category": t("category"),
            "severity": t("severity"),
            "rule_id": t("rule_id"),
            "title": t("title"),
            "hostname": t("hostname"),
            "device_id": t("device_id"),
            "konnektor_id": t("konnektor_id"),
            "hardware_id": t("hardware_id"),
            "instance_id": t("instance_id"),
            "file": t("file"),
            "line": t("line"),
            "timestamp": t("timestamp"),
            "confidence": t("confidence"),
            "evidence": t("evidence"),
            "recommendation": t("recommendation"),
        }

        display_view = view.rename(columns=column_translations)
        st.dataframe(display_view, use_container_width=True, hide_index=True)


        for finding in result["findings"]:
            with st.expander(f"🔴 ERROR · {finding.category} · {finding.source} · {finding.title} · line {finding.line_number}"):
                st.write(f"**Rule:** `{finding.rule_id}`")
                st.write(f"**Description:** {finding.description}")
                st.write(f"**Evidence:** `{finding.evidence}`")
                st.write(f"**Recommendation:** {finding.recommendation}")
                st.caption(f"Confidence: {finding.confidence} · File: {finding.file_name}")

with tab_timeline:
    st.subheader("Event timeline")
    timed = [e for e in result["events"] if e.timestamp is not None]
    if timed:
        tdf = pd.DataFrame([{
            "timestamp": e.timestamp,
            "source": e.source,
            "level": e.level,
            "component": e.component,
            "message": e.message[:180]
        } for e in timed])
        st.plotly_chart(px.scatter(
            tdf, x="timestamp", y="source", color="level",
            hover_data=["component", "message"], title="Parsed log event timeline"
        ), use_container_width=True)
        st.dataframe(tdf.sort_values("timestamp"), use_container_width=True, hide_index=True)
    else:
        st.info("No supported timestamps were found. Add a parser for your log timestamp format.")

with tab_correlation:
    st.subheader("Time-based correlation leads")
    st.caption("Events close in time are grouped for investigation. Temporal proximity does not prove causation.")
    if result["correlations"]:
        for idx, group in enumerate(result["correlations"], 1):
            with st.expander(f"Group {idx}: {group['finding_count']} findings · {group['start']} → {group['end']}"):
                st.write("**Sources:** " + ", ".join(group["sources"]))
                st.write("**Rules:** " + ", ".join(group["rule_ids"]))
                for evidence in group["evidence"]:
                    st.code(evidence)
    else:
        st.info("No groups of two or more timestamped findings were found in the selected time window.")
    st.subheader("Root-cause hypotheses")
    st.caption("These are investigative leads, not confirmed causes.")
    if result.get("hypotheses"):
        for item in result["hypotheses"]:
            with st.expander(item["hypothesis"]):
                st.write(item["basis"])
                st.write("**Affected instances:** " + ", ".join(item["affected_instances"]))
                st.caption(item["confidence"])
    else:
        st.info("Insufficient cross-instance evidence to generate a root-cause hypothesis.")

with tab_inventory:
    st.subheader("Card certificate validity")
    st.caption("Expired cards are highlighted RED. Validity is only classified when an explicit, labelled expiry/notAfter date is present in the logs; missing dates are not assumed valid.")
    card_records = extract_card_validity(documents)
    if card_records:
        for card in card_records:
            if card.status == "EXPIRED":
                st.error(f"🔴 EXPIRED — {card.card_type} · expiry: {card.expiry_date} · {card.source_file}:{card.line_number}")
            elif card.status == "VALID":
                st.success(f"🟢 VALID — {card.card_type} · expiry: {card.expiry_date} · {card.source_file}:{card.line_number}")
            else:
                st.warning(f"UNKNOWN — {card.card_type} · {card.source_file}:{card.line_number}")
        st.dataframe(pd.DataFrame([c.to_dict() for c in card_records]), use_container_width=True, hide_index=True)
    else:
        st.info("No explicit card expiry dates were found in the uploaded logs. This does not mean that all cards are valid.") 
    st.divider()
    st.subheader("Identifier Inventory")
    st.caption(
        "All distinct identifiers detected across uploaded logs. "
        "Repeated values are grouped, with source evidence retained. "
        "Identifiers are not automatically assumed to belong to the same device."
    )

    identifier_records = result.get("identifier_inventory", [])

    if identifier_records:
        identifier_rows = []

        for item in identifier_records:
            evidence_text = "; ".join(
                f"{entry['file']}:{entry['line']}"
                + (
                    f" ({entry['timestamp']})"
                    if entry.get("timestamp")
                    else ""
                )
                for entry in item.get("evidence", [])
            )

            identifier_rows.append({
                "Identifier Type": item["identifier_type"],
                "Value": item["value"],
                "Occurrences": item["occurrences"],
                "Source Evidence": evidence_text or "Not available",
            })

        st.dataframe(
            pd.DataFrame(identifier_rows),
            use_container_width=True,
            hide_index=True,
        )
    else:
        st.info("No identifier inventory is available for the uploaded logs.")

    st.divider()
    st.subheader("HSK / HSM instance comparison")
    st.caption(
        "Orange = instance with detected errors. "
        "Green = no matching errors in the supplied logs only. "
        "Grey = physical identity could not be established."
    )

    if result.get("instances"):
        for row in result["instances"]:
            if row["color"] == "ORANGE":
                st.warning(
                    f"🟠 AFFECTED — {row['instance']} · "
                    f"{row['findings']} findings · {row['events']} events"
                )
            elif row["color"] == "GREEN":
                st.success(
                    f"🟢 {t('no_matched_errors')} — "
                    f"{row['instance']} · {row['events']} events"
                )
            else:
                st.info(
                    f"⚪ {t('unknown_identity')} — "
                    f"{row['instance']} · {row['events']} events"
                )

        st.dataframe(
            pd.DataFrame(result["instances"]),
            use_container_width=True,
            hide_index=True,
        )
    else:
        st.info("No identifiable infrastructure instances were found in the uploaded logs.")

    st.subheader("Error frequency")
    if result.get("frequency"):
        freq = pd.DataFrame(result["frequency"])
        st.dataframe(freq, use_container_width=True, hide_index=True)
        st.plotly_chart(
            px.bar(
                freq,
                x="error",
                y="occurrences",
                color="category",
                title="Detected error frequency",
            ),
            use_container_width=True,
        )

    else:
        st.info("No identifiable infrastructure instances were found in the uploaded logs.")
    
with tab_ai:
    st.subheader("AI-assisted diagnostics")
    st.warning("AI is not connected in v0.2.0. No log content is sent to an external service.")
    st.write(
        "The intended next step is a local LLM + retrieval-augmented generation (RAG) adapter "
        "over approved, version-controlled technical documentation."
    )
    st.markdown("""
    **Planned safeguards**
    - Redact identifiers and secrets before model inference.
    - Provide the model only selected evidence and approved documentation.
    - Require citations to log lines and documentation passages.
    - Label outputs as hypotheses and retain human review.
    """)
    if result["findings"]:
        st.write("A compact evidence set that could be passed to a future local assistant:")
        st.json([f.to_dict() for f in result["findings"][:10]])

with tab_export:
    st.subheader("Export analysis")
    fdf = findings_dataframe(result["findings"])
    st.download_button(
        "Download findings CSV",
        data=fdf.to_csv(index=False).encode("utf-8"),
        file_name="tili_findings.csv",
        mime="text/csv"
    )
    st.download_button(
        "Download full analysis JSON",
        data=report_json(result).encode("utf-8"),
        file_name="tili_analysis.json",
        mime="application/json"
    )
    st.caption("Exports may contain sensitive log evidence. Store and share them according to your organisation's policies.")

st.divider()
st.caption(f"TILI v{APP_VERSION} · Regex matches are diagnostic leads, not proof of root cause. Validate against approved product documentation and complete logs.")
