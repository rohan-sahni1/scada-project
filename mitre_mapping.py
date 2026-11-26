import streamlit as st
import pandas as pd


MITRE_TECHNIQUES = [
    {
        "Technique ID": "T1692.001",
        "Technique": "Unauthorized Command Message",
        "Investigation": "Review control commands and authorization logs."
    },
    {
        "Technique ID": "T1692.002",
        "Technique": "Unauthorized Reporting Message",
        "Investigation": "Verify reported sensor values against trusted measurements."
    },
    {
        "Technique ID": "T0836",
        "Technique": "Modify Parameter",
        "Investigation": "Review unexpected changes to device settings."
    },
    {
        "Technique ID": "T0831",
        "Technique": "Manipulation of Control",
        "Investigation": "Investigate unexpected changes in process behavior."
    }
]



def show_mitre_intelligence(predicted_class):

    st.markdown("""
    <style>
    .st-key-mitre_attack_panel,
    .st-key-mitre_natural_panel,
    .st-key-mitre_normal_panel {
        background: rgba(8, 20, 38, 0.92);
        border: 1px solid rgba(0, 212, 255, 0.45);
        border-radius: 12px;
        padding: 20px;
        margin-top: 12px;
    }
    </style>
    """, unsafe_allow_html=True)

    if predicted_class == "Attack":

        with st.container(key="mitre_attack_panel"):

            st.subheader("MITRE ATT&CK for ICS")

            st.warning(
                "Potential cyber threat - Security investigation required."
            )

            st.markdown("**Candidate Technique References**")

            st.caption(
                "Candidate technique references only. "
                "The classifier does not identify specific attack subtypes."
            )

            st.dataframe(
                pd.DataFrame(MITRE_TECHNIQUES),
                hide_index=True,
                width="stretch"
            )

            st.divider()

            st.markdown("**Recommended Security Actions**")

            st.markdown("""
- Review security and control panel logs.
- Verify sensor readings and relay activity.
- Investigate unauthorized control commands.
- Escalate suspicious activity to the security team.
            """)

            st.markdown(
                "[Official MITRE ATT&CK for ICS Matrix]"
                "(https://attack.mitre.org/matrices/ics/)"
            )

    elif predicted_class == "Natural":

        with st.container(key="mitre_natural_panel"):

            st.subheader("Equipment Fault Assessment")

            st.warning(
                "Potential equipment fault - Maintenance review required."
            )

            st.markdown("**Recommended Maintenance Actions**")

            st.markdown("""
- Inspect equipment and sensor readings.
- Review protective relay activity.
- Notify the maintenance team.
            """)

            st.caption(
                "No MITRE attack technique assigned to this prediction."
            )

    elif predicted_class == "NoEvents":

        with st.container(key="mitre_normal_panel"):

            st.subheader("Normal Operation Assessment")

            st.success("Model predicts normal operation.")

            st.caption(
                "Continue routine monitoring. "
                "No MITRE attack technique assigned."
            )
