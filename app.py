import os
import base64
import numpy as np
import pandas as pd
import joblib
import streamlit as st
import plotly.express as px
import plotly.graph_objects as go

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

k1, k2, k3, k4 = st.columns(4)
k1.metric("Records analysed", f"{N_RECORDS:,}")
k2.metric("Features", len(bundle["features"]))
k3.metric("Classes", len(classes))
if comp is not None and "Macro F1" in comp.columns:
    best = comp.sort_values("Macro F1", ascending=False).iloc[0]
    k4.metric(
    f"Best Model: {best['Model']}",
    f"{best['Macro F1']:.3f}",
    help=f"Model: {best['Model']} | Macro F1 Score"
)
else:
    k4.metric("Best model", "see notebook")

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
        "🔎 Live classifier",
        "📊 Model comparison",
        "🎯 Evaluation",
        "🧠 Features & autoencoder",
        "📁 Dataset"
    ],
    label_visibility="collapsed"
)

tab_live = st.container() if page == "🔎 Live classifier" else st.empty()
tab_comp = st.container() if page == "📊 Model comparison" else st.empty()
tab_eval = st.container() if page == "🎯 Evaluation" else st.empty()
tab_feat = st.container() if page == "🧠 Features & autoencoder" else st.empty()
tab_data = st.container() if page == "📁 Dataset" else st.empty()

# ================================================================== TAB 1
if page == "🔎 Live classifier":
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
                st.subheader("Summary")
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
                    yaxis_title="Number of Records"
                )

                fig.update_traces(
                    hovertemplate="<b>%{x}</b><br>Records: %{y}<extra></extra>"
                )
                graph_col1, graph_col2 = st.columns(2, gap="medium")

                with graph_col1:
                    with st.container(border=True):
                        st.plotly_chart(fig, use_container_width=True)
                # Dynamic anomaly score monitoring graph
                st.subheader("Anomaly Score Monitoring")

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
                    hovermode="x unified"
                )

                with graph_col2:
                    with st.container(border=True):
                        st.plotly_chart(anomaly_fig, use_container_width=True)
                # Dynamic sensor monitoring graph
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
                    hovermode="x unified"
                )

                st.plotly_chart(sensor_fig, use_container_width=True)
                st.dataframe(out)
                st.download_button("Download results", out.to_csv(index=False), "predictions.csv")

# ================================================================== TAB 2
if page == "📊 Model comparison":
    st.subheader("Five classifiers, same train/test split")
    if comp is None:
        st.info("`classifier_comparison.csv` not found. Run the comparison cell in the notebook.")
    else:
        comp_sorted = comp.sort_values("Macro F1", ascending=False).reset_index(drop=True)
        st.dataframe(comp_sorted)
        st.bar_chart(
        comp_sorted,
        x="Model",
        y=["Macro F1", "Natural recall"],
        horizontal=True,
        stack=False,
        x_label="Score",
        y_label="Classifier"
        )

        

# ================================================================== TAB 3
if page == "🎯 Evaluation":
    st.subheader("Random Forest: where it is right and wrong")
    left, right = st.columns(2)
    with left:
        show_image("Confusion matrix (rows = actual, columns = predicted)",
                   "outputs/confusion_matrix.png", "confusion_matrix.png")
    with right:
        rep = load_csv("outputs/classification_report.csv", index_col=0)
        if rep is None:
            st.info("Per-class table not found. Run the optional last notebook cell (saves the report tables).")
        else:
            st.markdown("**Precision / recall / F1 per class**")
            st.dataframe(rep)

    cmdf = load_csv("outputs/confusion_matrix.csv", index_col=0)
    if cmdf is not None and {"Attack", "Natural"} <= set(cmdf.index):
        nat_total = int(cmdf.loc["Natural"].sum())
        nat_as_atk = int(cmdf.loc["Natural", "Attack"])
        atk_total = int(cmdf.loc["Attack"].sum())
        atk_as_nat = int(cmdf.loc["Attack", "Natural"])
        st.markdown(
            f"**The two mistakes are not equally costly.** "
            f"{nat_as_atk:,} of {nat_total:,} faults ({nat_as_atk / nat_total:.1%}) were called attacks: "
            f"wasted effort for the security team. "
            f"{atk_as_nat:,} of {atk_total:,} attacks ({atk_as_nat / atk_total:.1%}) were called faults: "
            f"a real attack sent to the maintenance crew.")

    st.divider()
    st.subheader("Does the score hold on files the model never saw?")
    st.caption("Grouped cross-validation: each fold holds out whole files, so no near-identical "
               "neighbouring rows leak from training into testing.")
    cv = load_csv("outputs/grouped_cv_results.csv")
    if cv is None:
        st.info("Grouped CV results not found. Run the grouped cross-validation cell.")
    else:
        st.dataframe(cv)
        m1, m2, m3 = st.columns(3)
        m1.metric("Mean accuracy", f"{cv['accuracy'].mean():.3f}")
        m2.metric("Mean macro F1", f"{cv['macro_f1'].mean():.3f}")
        m3.metric("Mean Natural recall", f"{cv['natural_recall'].mean():.3f}")
        st.caption("Compare with the random-split result (macro F1 about 0.92). A big drop would mean "
                   "the random split was too optimistic; similar values mean the baseline is trustworthy.")

# ================================================================== TAB 4
if page == "🧠 Features & autoencoder":
    st.subheader("Which sensor readings does the Random Forest rely on?")
    fi = pd.Series(bundle["model"].feature_importances_,
                   index=bundle["features"]).sort_values(ascending=False)
    a, b_ = st.columns(2)
    with a:
        show_image("Top 15 features", "outputs/feature_importance.png", "feature_importance.png")
    with b_:
        st.markdown("**Top 15 features and their importance**")
        st.dataframe(fi.head(15).rename("importance").round(4))
        log_cols = [c for c in fi.index if "log" in c]
        st.metric(f"Importance held by the {len(log_cols)} log/alert columns",
                  f"{fi[log_cols].sum():.1%}")

    st.divider()
    st.subheader("Autoencoder: a second opinion that needs no attack labels")
    st.markdown(
        "Trained **only on normal operation**. It rebuilds normal readings well and unfamiliar ones "
        "badly; the rebuild error is the anomaly score. It can say *\"this is not normal\"*, but not "
        "whether the cause is an attack or a fault, so it complements the classifier.")
    ae_sum = load_csv("outputs/autoencoder_summary.csv")
    ae_rates = load_csv("outputs/autoencoder_flag_rates.csv", index_col=0)
    m1, m2 = st.columns(2)
    m1.metric("Alarm threshold", f"{threshold:.3f}")
    if ae_sum is not None:
        m2.metric("ROC-AUC (normal vs abnormal)", f"{float(ae_sum['roc_auc'].iloc[0]):.3f}")
    c_left, c_right = st.columns(2)
    with c_left:
        show_image("Reconstruction error by true class", "outputs/autoencoder_error_hist.png")
    with c_right:
        if ae_rates is None:
            st.info("Flag-rate table not found. Run the optional last notebook cell.")
        else:
            st.markdown("**Share of rows flagged as anomalous, by true class**")
            st.dataframe(ae_rates)
            st.bar_chart(ae_rates.iloc[:, 0])

# ================================================================== TAB 5
if page == "📁 Dataset":
    st.subheader("Power System Attack Dataset (3-class)")
    st.caption("Mississippi State University / Oak Ridge National Laboratory")
    d1, d2 = st.columns(2)
    counts = pd.DataFrame({"records": CLASS_COUNTS})
    counts["share"] = (counts["records"] / N_RECORDS).map("{:.1%}".format)
    with d1:
        st.markdown("**Class distribution**")
        st.dataframe(counts)
        st.bar_chart(counts["records"])
    with d2:
        st.markdown("**What is in the data**")
        st.markdown(
            "- 15 raw files merged into **78,377 records** x **128 features**, zero missing values\n"
            "- Readings from **4 PMUs** (R1 to R4): voltage and current magnitudes, phase angles\n"
            "- **12 log/alert columns**: control panel, relay and Snort intrusion-detector flags\n"
            "- Labels: `NoEvents` (normal), `Natural` (fault / disturbance), `Attack`\n"
            "- **Infinite values** in the four `R*-PA:Z` columns (8.04% of rows), replaced with "
            "column medians")

    with st.expander("Limitations to keep in mind"):
        st.markdown(
            "- Lab-scale power system data (2014 to 2015); results may not transfer to modern grids.\n"
            "- Classes are imbalanced (71% / 23% / 6%), so accuracy alone is misleading.\n"
            "- Offline analysis of recorded data, not real-time detection.\n"
            "- The demo events come from the held-out test rows, not from a live system.\n"
            "- Academic prototype, not a replacement for layered production security.")
