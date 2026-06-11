import pandas as pd
import streamlit as st

from triage_logic import add_missing_fields, get_classification_counts, triage_alerts


st.set_page_config(
    page_title="SOC Alert Triage Web App",
    layout="wide",
)


def read_uploaded_csv(uploaded_file):
    """Read an uploaded CSV file with pandas.

    Streamlit provides the uploaded file as an in-memory file-like object.
    This app reads that object directly and does not save the upload to disk.
    """
    try:
        return pd.read_csv(uploaded_file, encoding="utf-8-sig")
    except pd.errors.EmptyDataError:
        st.error("The uploaded CSV file is empty.")
    except pd.errors.ParserError:
        st.error("The uploaded file could not be parsed as a valid CSV.")
    except UnicodeDecodeError:
        st.error("The uploaded CSV encoding could not be read. Try saving it as UTF-8 CSV.")

    return None


def show_sidebar():
    """Explain the app in the sidebar for beginner analysts."""
    st.sidebar.title("How this tool works")
    st.sidebar.write(
        "Upload a Microsoft Defender or Microsoft Sentinel CSV export. "
        "The app fills missing fields, classifies each alert, and creates a short incident summary."
    )

    st.sidebar.subheader("Privacy warning")
    st.sidebar.warning(
        "Do not upload confidential, sensitive, personal, or client data unless you are authorised. "
        "For public deployments, assume uploaded data may be processed by the hosting environment."
    )

    st.sidebar.subheader("Classification")
    st.sidebar.write(
        "The app starts with the source Severity value, then checks the alert title and description "
        "for SOC keywords. The final classification uses the highest risk level found."
    )

    st.sidebar.subheader("Output")
    st.sidebar.write(
        "The final CSV includes the original alert data plus classification, reason, affected entity, "
        "recommended next action, and incident summary columns."
    )


def show_dashboard(triaged_alerts):
    """Display simple metric cards for the triaged alert set."""
    counts = get_classification_counts(triaged_alerts)

    total_col, low_col, medium_col, high_col, critical_col = st.columns(5)
    total_col.metric("Total alerts", len(triaged_alerts))
    low_col.metric("Low", counts["Low"])
    medium_col.metric("Medium", counts["Medium"])
    high_col.metric("High", counts["High"])
    critical_col.metric("Critical", counts["Critical"])


def main():
    show_sidebar()

    st.title("SOC Alert Triage Web App")
    st.warning(
        "Privacy Notice: This tool is for learning and demonstration purposes. "
        "Do not upload confidential, sensitive, client, government, or production "
        "security data unless you are authorised to do so."
    )
    st.info(
        "Disclaimer: This tool uses basic rule-based logic. It does not replace a SIEM, "
        "SOC analyst, incident responder, or formal investigation process."
    )
    st.write(
        "Upload a Defender or Sentinel CSV export, preview the alerts, triage them, "
        "and download the final analyst-ready CSV."
    )

    uploaded_file = st.file_uploader("Upload alert CSV", type=["csv"])

    if uploaded_file is None:
        st.info("Upload a CSV file to begin. You can use sample_alerts.csv to test the app.")
        return

    alerts = read_uploaded_csv(uploaded_file)
    if alerts is None:
        return

    if alerts.empty:
        st.error("The uploaded CSV has headers but no alert rows.")
        return

    st.subheader("Uploaded alert preview")
    st.dataframe(alerts.head(10), use_container_width=True)

    prepared_alerts, missing_fields = add_missing_fields(alerts)

    if missing_fields:
        st.warning(
            "Missing expected columns were filled with blank values: "
            + ", ".join(missing_fields)
        )

    if st.button("Triage alerts", type="primary"):
        triaged_alerts = triage_alerts(prepared_alerts)

        # The CSV is created in memory for the download button.
        # It is not permanently saved by the app.
        csv_data = triaged_alerts.to_csv(index=False).encode("utf-8")

        st.success("Triage complete.")
        st.subheader("Summary dashboard")
        show_dashboard(triaged_alerts)

        st.subheader("Triaged alerts")
        st.dataframe(triaged_alerts, use_container_width=True)

        st.download_button(
            label="Download triaged_alerts.csv",
            data=csv_data,
            file_name="triaged_alerts.csv",
            mime="text/csv",
        )


if __name__ == "__main__":
    main()
