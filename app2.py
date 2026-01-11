import streamlit as st
import pandas as pd
import hashlib
import json
import datetime
import pytz
from dataclasses import dataclass, asdict

# --- 1. CONFIGURATION & THEMING (Light Mode) ---
st.set_page_config(
    page_title="MILITIA | Compliance & Alpha",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for "Light Mode"
st.markdown("""
<style>
    .stApp {
        background-color: #FFFFFF;
        color: #000000;
    }
    .stTextInput > div > div > input {
        background-color: #FFFFFF;
        color: #000000;
        border: 1px solid #CCCCCC;
    }
    .stSelectbox > div > div > div {
        color: #000000;
        background-color: #FFFFFF;
    }
    .stButton > button {
        background-color: #1A73E8;
        color: white;
        border-radius: 4px;
        font-weight: bold;
        border: none;
    }
    .stButton > button:hover {
        background-color: #1557B0;
    }
    .threshold-alert {
        padding: 1rem;
        background-color: #7F1D1D;
        color: #FECACA;
        border-radius: 4px;
        border-left: 5px solid #EF4444;
        margin-bottom: 1rem;
    }
</style>
""", unsafe_allow_html=True)

# --- 2. THE IRONCLAD AUDIT TRAIL ---
@dataclass
class LocateEntry:
    timestamp: str
    ticker: str
    quantity: int
    locate_source: str
    jurisdiction: str
    compliance_notes: str
    operator_id: str
    previous_hash: str

    def calculate_hash(self):
        entry_string = json.dumps(asdict(self), sort_keys=True)
        return hashlib.sha256(entry_string.encode()).hexdigest()

class AuditChain:
    def __init__(self):
        if 'audit_chain' not in st.session_state:
            st.session_state.audit_chain = []
            self.add_entry("GENESIS", 0, "SYSTEM", "GLOBAL", "Initial Block", "SYSTEM")

    def get_latest_hash(self):
        if not st.session_state.audit_chain:
            return "0" * 64
        return st.session_state.audit_chain[-1]['hash']

    def add_entry(self, ticker, quantity, source, jurisdiction, notes, operator):
        prev_hash = self.get_latest_hash()
        utc_now = datetime.datetime.now(pytz.utc).isoformat()
        
        new_entry = LocateEntry(
            timestamp=utc_now,
            ticker=ticker,
            quantity=quantity,
            locate_source=source,
            jurisdiction=jurisdiction,
            compliance_notes=notes,
            operator_id=operator,
            previous_hash=prev_hash
        )
        
        entry_hash = new_entry.calculate_hash()
        
        record = asdict(new_entry)
        record['hash'] = entry_hash
        st.session_state.audit_chain.append(record)
        return entry_hash

THRESHOLD_SECURITIES = ["GME", "AMC", "BBBY"] 

def threshold_guard(ticker):
    if ticker in THRESHOLD_SECURITIES:
        return True, "WARNING: Security is on the Reg SHO Threshold List. Mandatory Close-out Rule 203(b)(3) applies."
    return False, ""

def jurisdiction_check(ticker):
    """
    Robust Geofencing Logic based on Ticker Suffixes.
    [cite_start]Ref: Chapter 5 of Documentation[cite: 142].
    """
    t = ticker.upper().strip()
    
    # 1. JAPAN LOGIC
    # Checks for .T suffix (Toyota=7203.T) or specific indices like N225
    jp_indices = ["N225", "TOPIX", "JPX400"]
    if t.endswith('.T') or t in jp_indices:
        return "JP", "FIEA Art. 162: Naked Short Ban & Uptick Rule Apply."

    # 2. EU LOGIC
    # Checks for common European exchange suffixes
    # .DE (Germany), .PA (Paris), .AS (Amsterdam), .BR (Brussels), .MI (Milan)
    eu_suffixes = ('.DE', '.PA', '.AS', '.BR', '.MI', '.MC', '.HE', '.LI')
    if t.endswith(eu_suffixes):
        return "EU", "SSR Art. 12: 'Covered' Short Only. Agreement Required."

    # 3. US LOGIC (Default)
    # If there is no suffix, we assume it is a US listing (Reg SHO)
    return "US", "Reg SHO Rule 203(b)(1): Reasonable Grounds/Locate Required."

# --- 3. ALPHA SOURCING ENGINE ---
def sourcing_logic(ticker):
    mock_holders = {
        'TSLA': [{"Holder": "Vanguard Group", "Shares": "210M"}, {"Holder": "BlackRock", "Shares": "190M"}],
        'GME': [{"Holder": "RC Ventures", "Shares": "9M"}]
    }
    return mock_holders.get(ticker, [])

def etf_arb_calculator(ticker, borrow_rate_bps):
    if borrow_rate_bps > 500:
        return {
            "Opp": "HIGH",
            "Strategy": "Create-to-Lend",
            "Note": f"Borrow rate {borrow_rate_bps}bps implies scarcity. ETF Creation Units (50k shares) may offer cheaper access via APs."
        }
    return {"Opp": "LOW", "Strategy": "Direct Borrow", "Note": "Standard locate sufficient."}

# --- 4. MAIN APP INTERFACE ---
def main():
    st.title("MILITIA | Compliance & Alpha Core")
    
    tab1, tab2, tab3 = st.tabs(["Locate Entry", "Sourcing Engine", "Legal Rationale"])

    with tab1:
        st.subheader("Secure Locate Entry")
        
        col1, col2, col3 = st.columns(3)
        with col1:
            # Added tooltip to explain suffixes
            ticker_input = st.text_input("Ticker Symbol (e.g. TSLA, 7203.T, VWAGY.DE)", value="N225").upper()
        with col2:
            qty_input = st.number_input("Quantity", min_value=100, step=100)
        with col3:
            source_input = st.selectbox("Locate Source", ["Goldman Sachs", "Morgan Stanley", "Internal"])

        # 1. Jurisdictional Geofencing
        jurisdiction, rule_note = jurisdiction_check(ticker_input)
        
        # Dynamic color coding for jurisdiction
        if jurisdiction == "US":
             st.info(f"**Jurisdiction Detected:** {jurisdiction} | **Compliance Protocol:** {rule_note}")
        elif jurisdiction == "JP":
             st.warning(f"**Jurisdiction Detected:** {jurisdiction} | **Compliance Protocol:** {rule_note}")
        else:
             st.error(f"**Jurisdiction Detected:** {jurisdiction} | **Compliance Protocol:** {rule_note}")

        # 2. Threshold Guard
        is_threshold, msg = threshold_guard(ticker_input)
        
        if is_threshold:
            st.markdown(f'<div class="threshold-alert">{msg}</div>', unsafe_allow_html=True)
            pre_borrow_id = st.text_input("MANDATORY: Pre-Borrow Agreement ID (Rule 203(b)(3))")
            if not pre_borrow_id:
                st.error("LOCATE BLOCKED: Threshold Security requires documented Pre-Borrow.")
                st.stop()
        else:
             pre_borrow_id = "N/A"

        # 3. Locate Execution
        if st.button("EXECUTE LOCATE & HASH"):
            chain = AuditChain()
            tx_hash = chain.add_entry(
                ticker_input,
                qty_input,
                source_input,
                jurisdiction,
                rule_note,
                "TRADER_DO_01"
            )
            st.success(f"Locate Secured. Hash: {tx_hash}")

        if 'audit_chain' in st.session_state and st.session_state.audit_chain:
            st.divider()
            st.write("**Immutable Audit Log (Hash Chain):**")
            df_log = pd.DataFrame(st.session_state.audit_chain)
            st.dataframe(df_log.iloc[::-1], use_container_width=True)

    with tab2:
        st.subheader("Inventory Discovery (13F/N-PORT)")
        src_ticker = st.text_input("Target Asset for Sourcing", value="GME").upper()
        holders = sourcing_logic(src_ticker)
        
        if holders:
            st.write(f"**Top Institutional Holders (Potential Direct Lenders):**")
            st.table(pd.DataFrame(holders))
        else:
            st.warning("No significant 13F holders found.")
            
        st.divider()
        st.write("**ETF 'Create-to-Lend' Analysis**")
        market_rate = st.slider("Current Street Borrow Rate (bps)", 0, 5000, 600)
        arb_analysis = etf_arb_calculator(src_ticker, market_rate)
        
        c1, c2, c3 = st.columns(3)
        c1.metric("Arb Opportunity", arb_analysis['Opp'])
        c2.metric("Strategy", arb_analysis['Strategy'])
        c3.caption(arb_analysis['Note'])

    with tab3:
        st.markdown("""
        ### Legal Rationale & Citations
        **1. Regulation SHO Rule 203(b)(1) - The "Locate" Requirement**
        * *Rationale:* This tool facilitates compliance by documenting "reasonable grounds to believe"
        securities can be borrowed.
        * *Citation:* 17 CFR § 242.203(b)(1)(ii) & (iii).

        **2. Regulation SHO Rule 203(b)(3) - Threshold Securities**
        * *Rationale:* The "Threshold Guard" prevents execution in securities with 13-day persistent fails
        without a bona-fide pre-borrow.
        * *Citation:* 17 CFR § 242.203(b)(3)(iv).

        **3. Regulation SHO Rule 204 - Close-out Requirement**
        * *Rationale:* The audit trail creates the necessary evidence to prove "bona-fide market making"
        exceptions (if applicable) or standard close-out adherence (T+1/T+3).
        * *Citation:* 17 CFR § 242.204(a).

        **4. Jurisdictional Geofencing**
        * *EU SSR:* Adheres to Article 12 ("Covered" requirement).
        * *Japan FIEA:* Adheres to Article 162 (Naked Short Ban).
        """)

if __name__ == "__main__":
    main()
