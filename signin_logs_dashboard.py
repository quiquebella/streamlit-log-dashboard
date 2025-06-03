import streamlit as st
import pandas as pd
import json
import numpy as np
import pydeck as pdk
import plotly.express as px

st.set_page_config(page_title="Azure AD Sign-in Logs", layout="wide")

st.title("🔐 Azure AD Sign-in Logs Viewer")
st.markdown("Visualize and analyze sign-in logs with KPIs, filters, failure analysis, MFA, device data, and geolocation.")

uploaded_file = st.file_uploader("📁 Upload the exported JSON file", type="json")

def parse_logs(logs):
    df = pd.DataFrame(logs)

    required_cols = [
        "conditionalAccessStatus", "userPrincipalName", "location", "createdDateTime", "userDisplayName",
        "appDisplayName", "riskState", "riskEventType_v2", "resourceDisplayName",
        "authenticationRequirement", "status", "mfaDetail", "deviceDetail"
    ]
    for col in required_cols:
        if col not in df.columns:
            df[col] = None

    df["Conditional Access"] = df["conditionalAccessStatus"].apply(lambda x: x.lower() if isinstance(x, str) else None)
    df["User"] = df["userPrincipalName"]

    def extract_lat(row):
        try: return row["geoCoordinates"]["latitude"]
        except: return None

    def extract_lon(row):
        try: return row["geoCoordinates"]["longitude"]
        except: return None

    df["lat"] = df["location"].apply(lambda x: extract_lat(x) if isinstance(x, dict) else None)
    df["lon"] = df["location"].apply(lambda x: extract_lon(x) if isinstance(x, dict) else None)

    return df

def show_failure_map(df):
    grouped = df.groupby(["lat", "lon"]).size().reset_index(name="count")
    grouped['radius'] = grouped['count'].apply(lambda x: max(500, np.sqrt(x)*20000))

    layer = pdk.Layer(
        "ScatterplotLayer",
        data=grouped,
        get_position=["lon", "lat"],
        get_fill_color=[255, 0, 0, 140],
        get_radius="radius",
        pickable=True,
        auto_highlight=True,
    )

    midpoint = (grouped["lat"].mean(), grouped["lon"].mean())

    view_state = pdk.ViewState(
        latitude=midpoint[0],
        longitude=midpoint[1],
        zoom=4,
        pitch=0,
    )

    r = pdk.Deck(
        layers=[layer],
        initial_view_state=view_state,
        tooltip={"text": "{count} failures"}
    )

    st.pydeck_chart(r)

if uploaded_file:
    try:
        raw_data = json.load(uploaded_file)
        logs = raw_data["value"] if isinstance(raw_data, dict) and "value" in raw_data else raw_data
        df = parse_logs(logs)

        with st.expander("🗺️ Geolocated Failure Map", expanded=True):
            all_ca_failures = df[(df["Conditional Access"] == "failure") & df["lat"].notnull() & df["lon"].notnull()][["lat", "lon"]]
            if not all_ca_failures.empty:
                show_failure_map(all_ca_failures)
            else:
                st.info("No geolocation data available for display.")

        with st.expander("📊 Weekly Executive Summary", expanded=True):
            total_logins = len(df)
            total_fails = df[df["Conditional Access"] == "failure"].shape[0]
            unique_users = df["User"].nunique()
            top_apps = df["appDisplayName"].value_counts().head(5)
            top_cities = df["location"].apply(lambda x: x.get("city") if isinstance(x, dict) else None).value_counts().head(5)

            col1, col2, col3 = st.columns(3)
            col1.metric("🔢 Total Sign-ins", total_logins)
            col2.metric("❌ CA Failures", total_fails)
            col3.metric("👤 Unique Users", unique_users)

            st.markdown("### 📱 Most Used Apps")
            st.plotly_chart(px.pie(values=top_apps.values, names=top_apps.index, title="Top Apps"))

            st.markdown("### 🌍 Most Frequent Cities")
            st.plotly_chart(px.pie(values=top_cities.values, names=top_cities.index, title="Top Cities"))

        with st.expander("📉 Failure Analysis by Reason", expanded=False):
            if "status" in df.columns:
                reasons = df["status"].apply(lambda x: x.get("failureReason") if isinstance(x, dict) else None)
                reason_counts = reasons[reasons != "Other."].value_counts().head(10)
                if not reason_counts.empty:
                    st.plotly_chart(px.pie(values=reason_counts.values, names=reason_counts.index, title="Most Common Failure Reasons"))
                else:
                    st.info("No failure reasons found in the data.")

        with st.expander("🔐 MFA Analysis", expanded=False):
            if "mfaDetail" in df.columns:
                df["mfaMethod"] = df["mfaDetail"].apply(lambda x: x.get("authMethod") if isinstance(x, dict) else None)
                mfa_usage = df["mfaMethod"].value_counts().head(10)
                mfa_total = df["mfaMethod"].notnull().sum()
                st.metric("🔐 Total with MFA", mfa_total)
                if not mfa_usage.empty:
                    st.plotly_chart(px.pie(values=mfa_usage.values, names=mfa_usage.index, title="MFA Methods Used"))
                else:
                    st.info("No MFA usage detected in the records.")

        with st.expander("📋 Full Log Table"):
            st.dataframe(df)

        with st.expander("⚠️ Users with Conditional Access Failures"):
            ca_failures = df[df["Conditional Access"] == "failure"]
            if not ca_failures.empty:
                ca_fail_count = ca_failures.groupby("User").size().reset_index(name="Failure Count").sort_values(by="Failure Count", ascending=False)
                selected_user = st.selectbox("Select a user to filter the log table", options=ca_fail_count["User"].tolist())
                st.table(ca_fail_count)

                filtered_df = df[df["User"] == selected_user]
                columns_to_show = [
                    "createdDateTime", "userDisplayName", "appDisplayName", "riskState",
                    "riskEventType_v2", "resourceDisplayName", "authenticationRequirement", "status", "location"
                ]
                st.markdown(f"### 📄 Log Details for User: `{selected_user}`")
                st.dataframe(filtered_df[columns_to_show])
            else:
                st.info("No Conditional Access failures found.")

    except Exception as e:
        st.error(f"Error processing the file: {e}")