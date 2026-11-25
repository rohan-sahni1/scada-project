import os
import base64
import numpy as np
import pandas as pd
import joblib
import streamlit as st
import plotly.express as px
import plotly.graph_objects as go
from mitre_mapping import show_mitre_intelligence

st.set_page_config(page_title="SCADA/ICS Intrusion & Fault Detection System",
                   page_icon="🛡️", layout="wide")

# ---------- CYBERSECURITY UI THEME ----------

# Load dashboard background image
bg_path = os.path.join(os.path.dirname(__file__), "assets", "scada_bg2.png")

with open(bg_path, "rb") as image_file:
    bg_base64 = base64.b64encode(image_file.read()).decode()

st.markdown("""
<style>
/* Main application background */

.stApp {
    background-image:
        linear-gradient(
            rgba(2, 6, 23, 0.78),
            rgba(2, 6, 23, 0.88)
        ),
        url("__SCADA_BG__");

    background-size: cover;
    background-position: center;
    background-attachment: fixed;
    color: #e6faff;
}

/* Main content area */
.block-container {
    padding-top: 2rem;
    padding-bottom: 2rem;
}

/* Sidebar */
section[data-testid="stSidebar"] {
    background: linear-gradient(180deg, #031725, #020b16);
    border-right: 1px solid #00d9ff;
}
/* Equal-width sidebar navigation buttons */

section[data-testid="stSidebar"] div[role="radiogroup"] {
    width: 100% !important;
}

section[data-testid="stSidebar"] div[role="radiogroup"] > label {
    width: 100% !important;
    min-height: 52px !important;
    box-sizing: border-box !important;
    display: flex !important;
    align-items: center !important;
    margin-bottom: 8px !important;
}

/* Make the inner button fill the entire width */
section[data-testid="stSidebar"] div[role="radiogroup"] > label > div {
    width: 100% !important;
    flex: 1 !important;
    box-sizing: border-box !important;
}
            
/* Headings */
h1, h2, h3 {
    color: #eaffff !important;
    text-shadow: 0 0 14px rgba(0, 229, 255, 0.25);
}

/* Metric cards */
div[data-testid="stMetric"] {
    background: linear-gradient(145deg, #071d2c, #04111f);
    border: 1px solid #00c8e8;
    border-radius: 14px;
    padding: 18px;
    box-shadow: 0 0 18px rgba(0, 216, 255, 0.12);
}

/* Graph container styling */
.st-key-prediction_panel,
.st-key-anomaly_panel,
.st-key-sensor_panel,
.st-key-dataset_table_panel,
.st-key-dataset_graph_panel,
.st-key-feature_panel,
.st-key-autoencoder_panel, 
.st-key-confusion_panel,
.st-key-performance_panel,
.st-key-validation_panel,
.st-key-comparison_table_panel,
.st-key-comparison_graph_panel{
    border: 1px solid #00c8e8 !important;
    border-radius: 14px !important;
    box-shadow: 0 0 18px rgba(0, 216, 255, 0.12) !important;
    background: linear-gradient(145deg, #071d2c, #04111f);
    padding: 18px !important;
    box-sizing: border-box;
}

/* Equal height for model comparison panels */
.st-key-comparison_table_panel,
.st-key-comparison_graph_panel {
    min-height: 425px !important;
}

/* Metric values */
div[data-testid="stMetricValue"] {
    color: #4deaff;
}

/* Buttons */
.stButton > button,
.stFormSubmitButton > button {
    background: #062838;
    color: #eaffff;
    border: 1px solid #00d9ff;
    border-radius: 9px;
    transition: all 0.2s ease;
}

.stButton > button:hover,
.stFormSubmitButton > button:hover {
    background: #07516a;
    color: white;
    border-color: #67f5ff;
    box-shadow: 0 0 14px rgba(0, 217, 255, 0.4);
}

/* Input fields */
div[data-baseweb="select"],
div[data-baseweb="input"] {
    border-radius: 9px;
}

/* Tab navigation */
button[data-baseweb="tab"] {
    color: #a5e9f5;
}

button[data-baseweb="tab"][aria-selected="true"] {
    color: #00e5ff;
}

/* Horizontal dividers */
hr {
    border-color: #164b60;
}
/* Cyan glowing graph containers */
[data-testid="stVerticalBlockBorderWrapper"],
[data-testid="stVerticalBlock"][style*="border"] {
    border: 1px solid #00d9ff !important;
    border-radius: 16px !important;
    box-shadow: 0 0 15px rgba(0, 217, 255, 0.25) !important;
    background: rgba(6, 22, 35, 0.35) !important;
}

/* Download results button */
div[data-testid="stDownloadButton"] button {
    background: #081c29 !important;
    color: #00d9ff !important;
    border: 1px solid #00d9ff !important;
    border-radius: 10px !important;
    box-shadow: 0 0 10px rgba(0, 217, 255, 0.20);
    font-weight: 600;
}

div[data-testid="stDownloadButton"] button:hover {
    background: #00d9ff !important;
    color: #061421 !important;
    box-shadow: 0 0 18px rgba(0, 217, 255, 0.50);
}
</style>
""".replace("__SCADA_BG__", f"data:image/png;base64,{bg_base64}"), unsafe_allow_html=True)

# ------------------------------------------------------------------ login
import json, hashlib, hmac, secrets

AUTH_FILE = "auth.json"
DEFAULT_PASSWORD = "12345"
USERS = ["admin", "security", "mechanical"]      # one login per team


def _hash(pw, salt_hex):
    return hashlib.pbkdf2_hmac("sha256", pw.encode(), bytes.fromhex(salt_hex), 200_000).hex()


def _new_entry(pw):
    salt = secrets.token_hex(16)
    return {"salt": salt, "hash": _hash(pw, salt)}


def _save_auth(auth):
    with open(AUTH_FILE, "w") as f:
        json.dump(auth, f)


def _load_auth():
    if os.path.exists(AUTH_FILE):
        with open(AUTH_FILE) as f:
            return json.load(f)
    auth = {u: _new_entry(DEFAULT_PASSWORD) for u in USERS}
    _save_auth(auth)
    return auth


def _correct(pw, entry):
    return hmac.compare_digest(_hash(pw, entry["salt"]), entry["hash"])


def require_login():
    if st.session_state.get("user"):
        return

    # Premium login screen
    st.markdown("""
    <style>
    /* Hide sidebar on login screen */
    section[data-testid="stSidebar"] {
        display: none !important;
    }

    /* Center the login content */
    .block-container {
        max-width: 520px !important;
        padding-top: 18vh !important;
    }

    /* Login heading */
    .login-heading {
        text-align: center;
        width: 100%;
        display: flex;
        align-items: center;
        justify-content: center;
        gap: 12px;
        font-size: 34px;
        font-weight: 800;
        color: #eaffff;
        text-shadow: 0 0 22px rgba(0, 229, 255, 0.35);
        margin-bottom: 8px;
}

    .login-subtitle {
        text-align: center;
        color: #8faabb;
        font-size: 14px;
        letter-spacing: 2px;
        margin-bottom: 18px;
        width: 100%;
        text-align: center;
    }

    /* Login form styling */
    div[data-testid="stForm"] {
        background: rgba(3, 20, 36, 0.95);
        border: 1px solid #00d9ff;
        border-radius: 18px;
        padding: 30px;
        box-shadow: 0 0 35px rgba(0, 217, 255, 0.12);
    }

    /* Login button */
    div[data-testid="stFormSubmitButton"] button {
        width: 100%;
        background: linear-gradient(90deg, #007eaa, #00c9e8);
        color: white;
        border: none;
        border-radius: 10px;
        font-weight: 700;
        min-height: 45px;
    }

    div[data-testid="stFormSubmitButton"] button:hover {
        background: #00d9ff;
        color: #00121f;
        box-shadow: 0 0 20px rgba(0, 217, 255, 0.4);
    }
    </style>
    """, unsafe_allow_html=True)

    st.markdown("""
    <div class="login-heading">🛡️ SCADA SECURITY</div>
    <div class="login-subtitle">INDUSTRIAL CONTROL SYSTEM</div>
    """, unsafe_allow_html=True)

    with st.form("login"):
        st.markdown("### 🔐 Secure Access")
        user = st.selectbox("User", USERS)
        pw = st.text_input("Password", type="password")
        ok = st.form_submit_button(
    "ACCESS CONTROL CENTER",
    use_container_width=True
)

    if ok:
        if _correct(pw, _load_auth()[user]):
            st.session_state["user"] = user
            st.rerun()
        else:
            st.error("Wrong password")

    st.stop()


def account_sidebar():
    user = st.session_state["user"]
    with st.sidebar:
        st.write(f"Signed in as **{user}**")
        with st.expander("Change password"):
            with st.form("change_pw", clear_on_submit=True):
                old = st.text_input("Current password", type="password")
                new = st.text_input("New password", type="password")
                new2 = st.text_input("Repeat new password", type="password")
                go = st.form_submit_button("Update")
            if go:
                auth = _load_auth()
                if not _correct(old, auth[user]):
                    st.error("Current password is wrong")
                elif len(new) < 5:
                    st.error("New password must be at least 5 characters")
                elif new != new2:
                    st.error("The two new passwords do not match")
                else:
                    auth[user] = _new_entry(new)
                    _save_auth(auth)
                    st.success("Password changed")
        if st.button("Log out"):
            st.session_state.clear()
            st.rerun()


require_login()
account_sidebar()
ROLE = st.session_state["user"]

# What the operator should do for each predicted class
RESPONSE = {
    "Attack":   ("Cyberattack",      "Escalate to the SECURITY team",  st.error),
    "Natural":  ("Natural fault",    "Dispatch the MAINTENANCE crew",  st.warning),
    "NoEvents": ("Normal operation", "No action needed",               st.success),
}

# Dataset facts we measured in the notebook
CLASS_COUNTS = {"Attack": 55663, "Natural": 18309, "NoEvents": 4405}
N_RECORDS = sum(CLASS_COUNTS.values())        # 78,377


# ------------------------------------------------------------------ helpers
def first_existing(*paths):
    for p in paths:
        if os.path.exists(p):
            return p
    return None


def load_csv(*paths, index_col=None):
    p = first_existing(*paths)
    return pd.read_csv(p, index_col=index_col) if p else None


def show_image(caption, *paths):
    p = first_existing(*paths)
    if p:
        st.image(p, caption=caption)
    else:
        st.info(f"Image not found yet: `{paths[0]}`. Run the notebook cell that creates it.")


@st.cache_resource
def load_bundle():
    return joblib.load("outputs/scada_bundle.joblib")


def score(df, b):
    """Predicted label, class probabilities and autoencoder error for each row."""
    X = df[b["features"]].replace([np.inf, -np.inf], np.nan)   # same cleaning as training
    Xi = b["imputer"].transform(X)                              # fill gaps with training medians
    proba = b["model"].predict_proba(Xi)                        # Random Forest
    labels = b["label_encoder"].inverse_transform(proba.argmax(axis=1))
    S = b["ae_scaler"].transform(Xi)                            # autoencoder anomaly score
    err = ((S - b["ae"].predict(S)) ** 2).mean(axis=1)
    return labels, proba, err


# ------------------------------------------------------------------ load
try:
    bundle = load_bundle()
except FileNotFoundError:
    st.error("Model file not found. Run the notebook cells first "
             "(they create `outputs/scada_bundle.joblib`).")
    st.stop()

classes = list(bundle["label_encoder"].classes_)
threshold = bundle["ae_threshold"]
comp = load_csv("classifier_comparison.csv", "outputs/classifier_comparison.csv")

# ------------------------------------------------------------------ header
st.markdown(
    """
    <div style="text-align:center; margin-bottom:8px;">
        <span style="font-size:32px; font-weight:800; color:#eaffff;">
            🛡️ SCADA/ICS Security Control Center
        </span>
    </div>
    <div style="text-align:center; margin-bottom:25px;">
        <span style="font-size:14px; color:#8faabb; letter-spacing:1px;">
            INTRUSION &amp; FAULT DETECTION SYSTEM | Random Forest + Autoencoder
        </span>
    </div>
    """,
    unsafe_allow_html=True
)


# ---------- Vertical sidebar navigation ----------

st.markdown("""
<style>
/* Sidebar background */
section[data-testid="stSidebar"] {
    background: linear-gradient(180deg, #001827, #020817);
    border-right: 1px solid #00d9ff55;
}

/* Navigation options - equal width */
section[data-testid="stSidebar"] div[role="radiogroup"] {
    width: 100% !important;
    display: flex !important;
    flex-direction: column !important;
    align-items: stretch !important;
}

section[data-testid="stSidebar"] div[role="radiogroup"] label {
    width: 100% !important;
    min-width: 100% !important;
    box-sizing: border-box !important;
    display: flex !important;
    align-items: center !important;
    background: #071d30;
    border: 1px solid #16445c;
    border-radius: 10px;
    padding: 12px 14px;
    margin-bottom: 8px;
    transition: all 0.2s ease;
}

/* Hover effect */
section[data-testid="stSidebar"] div[role="radiogroup"] label:hover {
    border-color: #00d9ff;
    background: #0b3046;
}

/* Selected navigation option */
section[data-testid="stSidebar"] div[role="radiogroup"] label:has(input:checked) {
    background: #07354a;
    border-color: #00d9ff;
    box-shadow: 0 0 12px #00d9ff33;
}
</style>
""", unsafe_allow_html=True)

st.sidebar.markdown("## 🛡️ CONTROL CENTER")
st.sidebar.caption("SCADA / ICS SECURITY MONITOR")

page = st.sidebar.radio(
    "NAVIGATION",
    [
        "Live classifier",
        "Model comparison",
        "Evaluation",
        "Model Diagnostics",
        "Dataset"
    ],
    label_visibility="collapsed"
)

tab_live = st.container() if page == "Live classifier" else st.empty()
tab_comp = st.container() if page == "Model comparison" else st.empty()
tab_eval = st.container() if page == "Evaluation" else st.empty()
tab_feat = st.container() if page == "Model Diagnostics" else st.empty()
tab_data = st.container() if page == "Dataset" else st.empty()

# ================================================================== TAB 1
if page == "Live classifier":
    mode = st.radio("Input", ["Pick a demo event", "Upload a CSV"], horizontal=True)

    if mode == "Pick a demo event":
        demo = pd.read_csv("outputs/demo_samples.csv")
        pool = demo
        if "marker" in demo.columns:
            pick = st.selectbox("Show events of type", ["All"] + classes)
            if pick != "All":
                pool = demo[demo["marker"] == pick].reset_index(drop=True)
        idx = int(st.number_input("Event number", 0, len(pool) - 1, 0))
        row = pool.iloc[[idx]]
        labels, proba, err = score(row, bundle)
        pred = labels[0]
        name, action, banner = RESPONSE[pred]

        banner(f"**{name}** — {action}")

        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Predicted class", pred)
        c2.metric("Confidence", f"{proba[0].max():.0%}")
        c3.metric("Anomaly score", f"{err[0]:.3f}")
        c4.metric("Actual (for demo)", row["marker"].iloc[0] if "marker" in row else "unknown")
        c3.caption(f"Alarm threshold: {threshold:.3f}")

        if err[0] > threshold:
            st.info("The autoencoder also flags this event as **unlike normal operation**.")
        else:
            st.info("The autoencoder sees this event as **within the normal range**.")

        st.divider()
        show_mitre_intelligence(pred)
        st.divider()
        st.subheader("Class probabilities")
        prob_df = pd.DataFrame({
            "Class": classes,
            "Probability": proba[0]
        })

        st.bar_chart(
        prob_df,
        x="Class",
        y="Probability",
        color="#00d9ff",
        horizontal=True
    )

    else:
        up = st.file_uploader("CSV with the same feature columns", type="csv")
        if up is None:
            st.info("Upload a CSV to classify many events at once.")
        else:
            df = pd.read_csv(up)
            missing = [c for c in bundle["features"] if c not in df.columns]
            if missing:
                st.error(f"{len(missing)} required columns are missing, e.g. {missing[:5]}")
            else:
                labels, proba, err = score(df, bundle)
                out = pd.DataFrame({"predicted": labels,
                                    "confidence": proba.max(axis=1).round(3),
                                    "anomaly_flag": err > threshold})
                # Store latest successful CSV analysis for Model Diagnostics
                st.session_state["diagnostic_data"] = pd.DataFrame({
                    "Predicted Class": labels,
                    "Anomaly Score": err,
                    "Anomaly Detected": err > threshold
                })

                st.session_state["diagnostic_filename"] = up.name
                st.subheader("Dataset Overview")
                st.caption(f"Uploaded dataset: {up.name}")

                total_records = len(out)
                attack_count = int((out["predicted"] == "Attack").sum())
                natural_count = int((out["predicted"] == "Natural").sum())
                normal_count = int((out["predicted"] == "NoEvents").sum())

                m1, m2, m3, m4 = st.columns(4)

                m1.metric("Total Records", f"{total_records:,}")
                m2.metric("Predicted Attacks", f"{attack_count:,}")
                m3.metric("Predicted Natural Faults", f"{natural_count:,}")
                m4.metric("Predicted NoEvents", f"{normal_count:,}")
                # Dynamic prediction distribution graph
                class_counts = (
                    out["predicted"]
                    .value_counts()
                    .reindex(["Attack", "Natural", "NoEvents"], fill_value=0)
                    .reset_index()
                )

                class_counts.columns = ["Class", "Count"]

                fig = px.bar(
                    class_counts,
                    x="Class",
                    y="Count",
                    color="Class",
                    color_discrete_map={
                        "Attack": "#ff4b6e",
                        "Natural": "#ffb347",
                        "NoEvents": "#00d9ff"
                    },
                    title="Prediction Distribution - Uploaded Dataset",
                    text="Count"
                )

                fig.update_layout(
                    template="plotly_dark",
                    paper_bgcolor="rgba(0,0,0,0)",
                    plot_bgcolor="rgba(0,0,0,0)",
                    font_color="#e6faff",
                    showlegend=False,
                    xaxis_title="Predicted Class",
                    yaxis_title="Number of Records",
                    height=350,
                    margin=dict(l=45, r=20, t=65, b=40),
                )

                fig.update_traces(
                    hovertemplate="<b>%{x}</b><br>Records: %{y}<extra></extra>"
                )
                graph_col1, graph_col2 = st.columns(2, gap="medium")

                with graph_col1:
                    with st.container(border=False, key="prediction_panel"):
                        st.plotly_chart(fig, use_container_width=True)
                # Dynamic anomaly score monitoring graph

                anomaly_df = pd.DataFrame({
                    "Record": np.arange(len(err)),
                    "Anomaly Score": err,
                    "Anomaly": err > threshold
                })

                anomaly_fig = go.Figure()

                # Plot anomaly scores
                anomaly_fig.add_trace(
                    go.Scatter(
                        x=anomaly_df["Record"],
                        y=anomaly_df["Anomaly Score"],
                        mode="lines",
                        name="Anomaly Score",
                        line=dict(color="#00d9ff", width=2)
                    )
                )

                # Highlight detected anomalies
                anomalies = anomaly_df[anomaly_df["Anomaly"]]

                anomaly_fig.add_trace(
                    go.Scatter(
                        x=anomalies["Record"],
                        y=anomalies["Anomaly Score"],
                        mode="markers",
                        name="Flagged Anomalies",
                        marker=dict(color="#ff4b6e", size=5)
                    )
                )

                # Autoencoder detection threshold
                anomaly_fig.add_hline(
                    y=threshold,
                    line_dash="dash",
                    line_color="#ffb347",
                    annotation_text="Anomaly Threshold"
                )

                anomaly_fig.update_layout(
                title="Anomaly Scores Across Uploaded Records",
                xaxis_title="Record Number",
                yaxis_title="Autoencoder Anomaly Score (Log Scale)",
                yaxis_type="log",
                template="plotly_dark",
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                font_color="#e6faff",
                hovermode="x unified",
                height=350,
                margin=dict(l=45, r=20, t=65, b=40),
                legend=dict(
                    orientation="h",
                    y=1.02,
                    x=0
                )
            )

                with graph_col2:
                    with st.container(border=False, key="anomaly_panel"):
                        st.plotly_chart(anomaly_fig, use_container_width=True)
                # Dynamic sensor monitoring graph
                with st.container(border=False, key="sensor_panel"):
                    st.subheader("Interactive Sensor Monitoring")

                    sensor_columns = [c for c in bundle["features"] if c in df.columns]

                    selected_sensor = st.selectbox(
                        "Select a sensor to monitor",
                        sensor_columns,
                        key="uploaded_sensor_selector"
                    )

                    sensor_values = pd.to_numeric(
                        df[selected_sensor], errors="coerce"
                    ).replace([np.inf, -np.inf], np.nan)

                    sensor_fig = go.Figure()

                    sensor_fig.add_trace(
                        go.Scatter(
                            x=np.arange(len(sensor_values)),
                            y=sensor_values,
                            mode="lines",
                            name=selected_sensor,
                            line=dict(color="#00d9ff", width=2)
                        )
                    )

                    sensor_fig.update_layout(
                        title=f"Sensor Readings: {selected_sensor}",
                        xaxis_title="Record Number",
                        yaxis_title="Sensor Reading",
                        template="plotly_dark",
                        paper_bgcolor="rgba(0,0,0,0)",
                        plot_bgcolor="rgba(0,0,0,0)",
                        font_color="#e6faff",
                        hovermode="x unified",
                        height=320,
                        margin=dict(l=45, r=20, t=50, b=40),
                    )

                    st.plotly_chart(sensor_fig, use_container_width=True)
                st.subheader("Prediction Results")

                st.dataframe(
                    out.style.set_properties(**{
                        "background-color": "#071d2c",
                        "color": "#e6faff"
                    }),
                    column_config={
                        "predicted": "Predicted Class",
                        "confidence": st.column_config.NumberColumn(
                            "Confidence",
                            format="percent"
                        ),
                        "anomaly_flag": "Anomaly Detected"
                    },
                    hide_index=True,
                    width="stretch",
                    height=300
                )
                left_space, download_col, right_space = st.columns([2, 1, 2])

                with download_col:
                    st.download_button(
                        "Download results",
                        out.to_csv(index=False),
                        "predictions.csv",
                        width="stretch"
                    )
                st.divider()

                st.subheader("Threat Intelligence Summary")
                st.caption("Investigation guidance based on predicted event classes.")

                if attack_count > 0:
                    st.warning(
                        f"{attack_count:,} records classified as potential cyber attacks."
                    )
                    show_mitre_intelligence("Attack")

                if natural_count > 0:
                    st.info(
                        f"{natural_count:,} records classified as potential natural faults."
                    )
                    show_mitre_intelligence("Natural")

                if attack_count == 0 and natural_count == 0 and normal_count > 0:
                    show_mitre_intelligence("NoEvents")

# ================================================================== TAB 2
if page == "Model comparison":
    st.subheader("Model Comparison")
    st.caption("Historical classifier performance — held-out test results")

    if comp is None:
        st.warning("Classifier comparison results are unavailable.")

    else:
        comp_sorted = comp.sort_values(
            "Macro F1", ascending=False
        ).reset_index(drop=True)

        best_model = comp_sorted.iloc[0]

        m1, m2, m3 = st.columns(3)

        m1.metric("Best Model", best_model["Model"])
        m2.metric("Best Accuracy", f"{comp_sorted['Accuracy'].max():.1%}")
        m3.metric("Best Macro F1", f"{best_model['Macro F1']:.3f}")

        left, right = st.columns(2)

        with left:
            with st.container(key="comparison_table_panel"):
                st.markdown("**Classifier Performance**")

                display_comp = comp_sorted[
                    ["Model", "Accuracy", "Macro F1", "Natural recall"]
                ].copy()

                st.dataframe(
                    display_comp,
                    hide_index=True,
                    width="stretch"
                )

                st.caption(
                    "SVM was trained using a 20,000-record subsample."
                )

        with right:
            with st.container(key="comparison_graph_panel"):
                st.markdown("**Performance Comparison**")

                comparison_fig = go.Figure()

                for metric, color in [
                    ("Accuracy", "#00c8e8"),
                    ("Macro F1", "#ffb347"),
                    ("Natural recall", "#527fdb")
                ]:
                    comparison_fig.add_trace(go.Bar(
                        y=comp_sorted["Model"],
                        x=comp_sorted[metric],
                        name=metric,
                        orientation="h",
                        marker_color=color,
                        hovertemplate="%{y}<br>Score: %{x:.3f}<extra></extra>"
                    ))

                comparison_fig.update_layout(
                    barmode="group",
                    paper_bgcolor="rgba(0,0,0,0)",
                    plot_bgcolor="rgba(0,0,0,0)",
                    font=dict(color="#e6f4ff"),
                    xaxis=dict(
                        title="Score",
                        range=[0, 1],
                        gridcolor="rgba(255,255,255,0.10)"
                    ),
                    yaxis=dict(
                        autorange="reversed",
                        title=None,
                        automargin=True
                    ),
                    legend=dict(
                        orientation="h",
                        y=1.12,
                        x=0,
                        font=dict(size=11)
                    ),
                    height=340,
                    margin=dict(l=10, r=15, t=45, b=40)
                )

                st.plotly_chart(
                    comparison_fig,
                    width="stretch"
                )

        

# ================================================================== TAB 3
if page == "Evaluation":
    st.subheader("Model Evaluation")
    st.caption("Random Forest — Held-out Test Performance")

    classes = ["Attack", "Natural", "NoEvents"]

    cmdf = load_csv(
        "outputs/confusion_matrix.csv", index_col=0
    )

    if cmdf is None:
        cmdf = pd.DataFrame(
            [
                [10936, 190, 7],
                [902, 2758, 2],
                [48, 4, 829]
            ],
            index=classes,
            columns=classes
        )
        st.caption("Using recorded baseline confusion matrix.")

    cmdf = cmdf.loc[classes, classes]
    cm = cmdf.to_numpy()

    # Calculate per-class performance
    performance = []

    for i, cls in enumerate(classes):
        tp = cm[i, i]
        predicted = cm[:, i].sum()
        actual = cm[i, :].sum()

        precision = tp / predicted if predicted else 0
        recall = tp / actual if actual else 0

        f1 = (
            2 * precision * recall / (precision + recall)
            if precision + recall else 0
        )

        performance.append({
            "Class": cls,
            "Precision": precision,
            "Recall": recall,
            "F1 Score": f1,
            "Support": int(actual)
        })

    report = pd.DataFrame(performance)

    accuracy = cm.diagonal().sum() / cm.sum()
    macro_f1 = report["F1 Score"].mean()
    natural_recall = report.loc[
        report["Class"] == "Natural", "Recall"
    ].iloc[0]

    # Performance metrics
    m1, m2, m3 = st.columns(3)

    m1.metric("Accuracy", f"{accuracy:.1%}")
    m2.metric("Macro F1", f"{macro_f1:.3f}")
    m3.metric("Natural Recall", f"{natural_recall:.1%}")

    left, right = st.columns(2)

    # Confusion matrix
    with left:
        with st.container(key="confusion_panel"):
            st.markdown("**Confusion Matrix**")

            cm_fig = go.Figure(
                data=go.Heatmap(
                    z=cm,
                    x=classes,
                    y=classes,
                    text=cm,
                    texttemplate="%{text:,}",
                    colorscale=[
                        [0, "#102b3c"],
                        [0.4, "#007b99"],
                        [1, "#00c8e8"]
                    ],
                    showscale=False,
                    hovertemplate=(
                        "Actual: %{y}<br>"
                        "Predicted: %{x}<br>"
                        "Records: %{z:,}"
                        "<extra></extra>"
                    )
                )
            )

            cm_fig.update_layout(
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                font=dict(color="#e6f4ff"),
                xaxis_title="Predicted Class",
                yaxis_title="Actual Class",
                height=300,
                margin=dict(l=65, r=15, t=15, b=45)
            )

            cm_fig.update_yaxes(autorange="reversed")

            st.plotly_chart(cm_fig, width="stretch")

    # Per-class performance
    with right:
        with st.container(key="performance_panel"):
            st.markdown("**Per-Class Performance**")

            st.dataframe(
                report.round(3),
                hide_index=True,
                width="stretch"
            )

            p1, p2 = st.columns(2)

            p1.metric(
                "Correct Predictions",
                f"{int(cm.diagonal().sum()):,}"
            )

            p2.metric(
                "Incorrect Predictions",
                f"{int(cm.sum() - cm.diagonal().sum()):,}"
            )

    # Grouped cross-validation
    st.subheader("Grouped Cross-Validation")

    cv = load_csv("outputs/grouped_cv_results.csv")

    if cv is not None:
        cv_accuracy = cv["accuracy"].mean()
        cv_f1 = cv["macro_f1"].mean()
        cv_recall = cv["natural_recall"].mean()

        g1, g2, g3 = st.columns(3)

        g1.metric("Mean Accuracy", f"{cv_accuracy:.3f}")
        g2.metric("Mean Macro F1", f"{cv_f1:.3f}")
        g3.metric("Mean Natural Recall", f"{cv_recall:.3f}")

        with st.container(key="validation_panel"):
            st.markdown("**Random Split vs Grouped Validation**")

            comparison_fig = go.Figure()

            comparison_fig.add_trace(go.Bar(
                name="Random Split",
                x=["Accuracy", "Macro F1", "Natural Recall"],
                y=[accuracy, macro_f1, natural_recall],
                marker_color="#00c8e8",
                text=[accuracy, macro_f1, natural_recall],
                texttemplate="%{text:.3f}",
                textposition="auto"
            ))

            comparison_fig.add_trace(go.Bar(
                name="Grouped Validation",
                x=["Accuracy", "Macro F1", "Natural Recall"],
                y=[cv_accuracy, cv_f1, cv_recall],
                marker_color="#ffb347",
                text=[cv_accuracy, cv_f1, cv_recall],
                texttemplate="%{text:.3f}",
                textposition="auto"
            ))

            comparison_fig.update_layout(
                barmode="group",
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                font=dict(color="#e6f4ff"),
                yaxis=dict(
                    title="Score",
                    range=[0, 1],
                    gridcolor="rgba(255,255,255,0.12)"
                ),
                legend=dict(
                    orientation="h",
                    y=1.12,
                    x=0
                ),
                height=300,
                margin=dict(l=45, r=20, t=40, b=30)
            )

            st.plotly_chart(
                comparison_fig, width="stretch"
            )

        with st.expander("Detailed Validation Results"):
            st.dataframe(
                cv,
                hide_index=True,
                width="stretch"
            )

    else:
        st.warning("Grouped validation results unavailable.")
# ================================================================== TAB 4
if page == "Model Diagnostics":
    st.subheader("Model Diagnostics")

    fi = pd.Series(
        bundle["model"].feature_importances_,
        index=bundle["features"]
    ).sort_values(ascending=False)

    log_cols = [c for c in fi.index if "log" in c]

    left, right = st.columns(2)

    # RANDOM FOREST DIAGNOSTICS
    with left:
        with st.container(key="feature_panel"):
            st.markdown("**Random Forest — Feature Importance**")

            st.metric(
                "Log/Alert Feature Importance",
                f"{fi[log_cols].sum():.1%}"
            )

            top_features = fi.head(15).sort_values()

            feature_fig = go.Figure(go.Bar(
                x=top_features.values,
                y=top_features.index,
                orientation="h",
                marker_color="#00c8e8",
                hovertemplate=(
                    "Feature: %{y}<br>"
                    "Importance: %{x:.4f}<extra></extra>"
                )
            ))

            feature_fig.update_layout(
                template="plotly_dark",
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                xaxis_title="Feature Importance",
                height=400,
                margin=dict(l=90, r=20, t=20, b=40),
                font=dict(color="white")
            )

            st.caption("Trained Random Forest — Top 15 features")
            st.plotly_chart(feature_fig, width="stretch")

    # AUTOENCODER DIAGNOSTICS
    with right:
        with st.container(key="autoencoder_panel"):
            st.markdown("**Autoencoder Diagnostics**")

            metric1, metric2 = st.columns(2)

            metric1.metric(
                "Alarm Threshold",
                f"{threshold:.3f}"
            )

            if "diagnostic_data" in st.session_state:

                diag = st.session_state["diagnostic_data"]

                metric2.metric(
                    "Flagged Records",
                    f"{diag['Anomaly Detected'].sum():,}"
                )

                st.caption(
                    "Latest analysed CSV: "
                    + st.session_state["diagnostic_filename"]
                )

                anomaly_fig = go.Figure()

                anomaly_fig.add_trace(go.Scatter(
                    x=list(range(len(diag))),
                    y=diag["Anomaly Score"].clip(lower=1e-12),
                    mode="lines",
                    name="Anomaly Score",
                    line=dict(color="#00c8e8", width=1.5)
                ))

                anomaly_fig.add_hline(
                    y=threshold,
                    line_dash="dash",
                    line_color="#ffb347",
                    annotation_text="Alarm Threshold"
                )

                anomaly_fig.update_layout(
                    template="plotly_dark",
                    paper_bgcolor="rgba(0,0,0,0)",
                    plot_bgcolor="rgba(0,0,0,0)",
                    xaxis_title="Record Number",
                    yaxis_title="Anomaly Score",
                    yaxis_type="log",
                    height=400,
                    margin=dict(l=50, r=20, t=20, b=40),
                    font=dict(color="white"),
                    showlegend=False
                )

                st.plotly_chart(
                    anomaly_fig,
                    width="stretch"
                )

            else:
                st.info(
                    "Upload a compatible CSV in Live Classifier "
                    "to view dataset-specific diagnostics."
                )

                show_image(
                    "Historical Reconstruction Error",
                    "outputs/autoencoder_error_hist.png"
                )

# ================================================================== TAB 5
if page == "Dataset":
    st.subheader("Power System Attack Dataset (3-class)")
    st.caption("Mississippi State University / Oak Ridge National Laboratory")
    m1, m2, m3 = st.columns(3)

    m1.metric("Total Records", "78,377")
    m2.metric("Input Features", "128")
    m3.metric("Dataset Files", "15")
    d1, d2 = st.columns(2)
    counts = pd.DataFrame({"records": CLASS_COUNTS})
    counts["share"] = (counts["records"] / N_RECORDS).map("{:.1%}".format)
    with d1:
        with st.container(height=380, key="dataset_table_panel"):
            st.markdown("**Class Distribution**")

            display_counts = counts.reset_index()
            display_counts.columns = ["Class", "Records", "Share"]

            st.dataframe(
                display_counts.style.set_properties(**{
                    "background-color": "#071d2c",
                    "color": "#e6faff"
                }),
                hide_index=True,
                width="stretch",
                height="auto"
            )

    with d2:
        with st.container(height=380, key="dataset_graph_panel"):
            st.markdown("**Dataset Distribution Graph**")

            dataset_fig = px.bar(
                x=counts.index,
                y=counts["records"],
                color=counts.index,
                text=counts["records"],
                color_discrete_map={
                    "Attack": "#ff4b6e",
                    "Natural": "#ffb347",
                    "NoEvents": "#00d9ff"
                }
            )

            dataset_fig.update_layout(
                template="plotly_dark",
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                font_color="#e6faff",
                showlegend=False,
                xaxis_title="Event Class",
                yaxis_title="Number of Records",
                height=300,
                margin=dict(l=45, r=20, t=25, b=40)
            )

            dataset_fig.update_traces(
                textposition="auto",
                texttemplate="%{y:,}",
                hovertemplate="Class: %{x}<br>Records: %{y:,}<extra></extra>"
            )

            st.plotly_chart(dataset_fig, width="stretch")