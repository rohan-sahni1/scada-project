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

    st.subheader("MITRE ATT&CK for ICS")

    if predicted_class == "Attack":

        st.warning(
            "Potential cyber threat - Security investigation required."
        )

        st.caption(
            "Candidate technique references only. "
            "The classifier does not identify specific attack subtypes."
        )

        st.dataframe(
            pd.DataFrame(MITRE_TECHNIQUES),
            hide_index=True,
            width="stretch"
        )

        st.markdown("**Recommended Actions**")

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

        st.warning(
            "Potential equipment fault - Maintenance review required."
        )

        st.markdown("""
        - Inspect equipment and sensor readings.
        - Review protective relay activity.
        - Notify the maintenance team.
        """)

        st.caption(
            "No MITRE attack technique assigned to this prediction."
        )

    elif predicted_class == "NoEvents":

        st.success("Model predicts normal operation.")

        st.caption(
            "Continue routine monitoring. "
            "No MITRE attack technique assigned."
        )