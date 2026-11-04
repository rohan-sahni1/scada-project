import os
import numpy as np
import pandas as pd
import joblib
import streamlit as st

st.set_page_config(page_title="SCADA/ICS Intrusion & Fault Detection System",
                   page_icon="🛡️", layout="wide")

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
    st.title("🔐 Sign in")
    with st.form("login"):
        user = st.selectbox("User", USERS)
        pw = st.text_input("Password", type="password")
        ok = st.form_submit_button("Log in")
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
st.title("🛡️ SCADA/ICS Intrusion & Fault Detection System")
st.caption("Normal operation vs natural fault vs cyberattack — Random Forest classifier "
           "plus an autoencoder anomaly check")

k1, k2, k3, k4 = st.columns(4)
k1.metric("Records analysed", f"{N_RECORDS:,}")
k2.metric("Features", len(bundle["features"]))
k3.metric("Classes", len(classes))
if comp is not None and "Macro F1" in comp.columns:
    best = comp.sort_values("Macro F1", ascending=False).iloc[0]
    k4.metric(f"Best model: {best['Model']}", f"macro F1 {best['Macro F1']:.3f}")
else:
    k4.metric("Best model", "see notebook")

tab_live, tab_comp, tab_eval, tab_feat, tab_data = st.tabs([
    "🔎 Live classifier", "📊 Model comparison", "🎯 Evaluation",
    "🧠 Features & autoencoder", "📁 Dataset",
])

# ================================================================== TAB 1
with tab_live:
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
        st.bar_chart(pd.Series(proba[0], index=classes))

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
                st.bar_chart(out["predicted"].value_counts())
                st.dataframe(out)
                st.download_button("Download results", out.to_csv(index=False), "predictions.csv")

# ================================================================== TAB 2
with tab_comp:
    st.subheader("Five classifiers, same train/test split")
    if comp is None:
        st.info("`classifier_comparison.csv` not found. Run the comparison cell in the notebook.")
    else:
        comp_sorted = comp.sort_values("Macro F1", ascending=False).reset_index(drop=True)
        st.dataframe(comp_sorted)
        st.bar_chart(comp_sorted.set_index("Model")[["Macro F1", "Natural recall"]])
        base_acc = CLASS_COUNTS["Attack"] / N_RECORDS
        st.markdown(
            f"- **Random Forest leads** on every measure. Many trees voting beat a single Decision Tree.\n"
            f"- **Why macro F1, not accuracy:** a model that always answers \"Attack\" already scores "
            f"**{base_acc:.3f} accuracy**, because 71% of records are attacks. Logistic Regression and "
            f"the SVM barely beat that.\n"
            f"- **Natural recall** (how many real faults are caught) is the weakest number for every model. "
            f"Separating faults from attacks is the hard part.\n"
            f"- Caveats: models ran with default settings (no tuning), and the SVM trained on a "
            f"20,000-row subsample.")

# ================================================================== TAB 3
with tab_eval:
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
with tab_feat:
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
with tab_data:
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
