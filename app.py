import streamlit as st

from scanner import scan_url


def main():
    st.set_page_config(
        page_title="ShieldX URL Scanner",
        page_icon="🛡️",
        layout="centered",
    )

    st.title("🛡️ ShieldX URL Scanner")
    st.write(
        "Check a URL for common warning signs. "
        "This is a heuristic check, not a guarantee that a site is safe."
    )

    with st.form("url_scan_form"):
        url = st.text_input(
            "URL to scan",
            placeholder="https://example.com",
        )
        submitted = st.form_submit_button("Scan URL", type="primary")

    if not submitted:
        return

    result = scan_url(url)

    if not result["valid"]:
        st.error(result["error"])
        return

    st.subheader("Scan results")
    st.write(f"**Hostname:** `{result['host']}`")

    level = result["level"]
    if level == "High":
        st.error(f"Risk level: {level}")
    elif level == "Medium":
        st.warning(f"Risk level: {level}")
    else:
        st.success(f"Risk level: {level}")

    st.progress(result["score"], text=f"Risk score: {result['score']}/100")

    if result["findings"]:
        st.markdown("**Warnings found**")
        for finding in result["findings"]:
            st.write(f"- {finding}")
    else:
        st.info("No warning signs were detected by these checks.")


if __name__ == "__main__":
    main()
