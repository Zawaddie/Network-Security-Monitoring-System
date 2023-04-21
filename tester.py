import streamlit as st
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

# Set up Streamlit app title and icon
st.set_page_config(page_title='Real-time IDS', page_icon=':shield:')

# Load in the trained model and the TRAIN_COLS variable
model = pd.read_pickle("rf_clf.pkl")


# load encoder
label_encoder = pd.read_pickle('encoder.pkl')
# TRAIN_COLS = ['src_ip', 'dst_ip', 'src_port', 'src_mac', 'dst_mac', 'timestamp']


TRAIN_COLS  =['Destination Port', 'Flow Duration', 'Total Fwd Packets',
       'Total Backward Packets', 'Total Length of Fwd Packets',
       'Total Length of Bwd Packets', 'Fwd Packet Length Max',
       'Fwd Packet Length Min', 'Fwd Packet Length Mean',
       'Fwd Packet Length Std', 'Bwd Packet Length Max',
       'Bwd Packet Length Min', 'Bwd Packet Length Mean',
       'Bwd Packet Length Std', 'Flow Bytes/s', 'Flow Packets/s',
       'Flow IAT Mean', 'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min',
       'Fwd IAT Total', 'Fwd IAT Mean', 'Fwd IAT Std', 'Fwd IAT Max',
       'Fwd IAT Min', 'Bwd IAT Total', 'Bwd IAT Mean', 'Bwd IAT Std',
       'Bwd IAT Max', 'Bwd IAT Min', 'Fwd PSH Flags', 'Fwd URG Flags',
       'Fwd Header Length', 'Bwd Header Length', 'Fwd Packets/s',
       'Bwd Packets/s', 'Min Packet Length', 'Max Packet Length',
       'Packet Length Mean', 'Packet Length Std', 'Packet Length Variance',
       'FIN Flag Count', 'SYN Flag Count', 'RST Flag Count', 'PSH Flag Count',
       'ACK Flag Count', 'URG Flag Count', 'CWE Flag Count', 'ECE Flag Count',
       'Down/Up Ratio', 'Average Packet Size', 'Avg Fwd Segment Size',
       'Avg Bwd Segment Size', 'Fwd Header Length.1', 'Subflow Fwd Packets',
       'Subflow Fwd Bytes', 'Subflow Bwd Packets', 'Subflow Bwd Bytes',
       'Init_Win_bytes_forward', 'Init_Win_bytes_backward', 'act_data_pkt_fwd',
       'min_seg_size_forward', 'Active Mean', 'Active Std', 'Active Max',
       'Active Min', 'Idle Mean', 'Idle Std', 'Idle Max', 'Idle Min']


rename_cols = {'flow_duration': 'Flow Duration',
 'flow_iat_mean': 'Flow IAT Mean',
 'flow_iat_std': 'Flow IAT Std',
 'flow_iat_max': 'Flow IAT Max',
 'flow_iat_min': 'Flow IAT Min',
 'fwd_iat_mean': 'Fwd IAT Mean',
 'fwd_iat_std': 'Fwd IAT Std',
 'fwd_iat_max': 'Fwd IAT Max',
 'fwd_iat_min': 'Fwd IAT Min',
 'bwd_iat_mean': 'Bwd IAT Mean',
 'bwd_iat_std': 'Bwd IAT Std',
 'bwd_iat_max': 'Bwd IAT Max',
 'bwd_iat_min': 'Bwd IAT Min',
 'fwd_psh_flags': 'Fwd PSH Flags',
 'bwd_psh_flags': 'Bwd PSH Flags',
 'fwd_urg_flags': 'Fwd URG Flags',
 'bwd_urg_flags': 'Bwd URG Flags',
 'cwe_flag_count': 'CWE Flag Count',
 'active_mean': 'Active Mean',
 'active_std': 'Active Std',
 'active_max': 'Active Max',
 'active_min': 'Active Min',
 'idle_mean': 'Idle Mean',
 'idle_std': 'Idle Std',
 'idle_max': 'Idle Max',
 'idle_min': 'Idle Min',
 'tot_fwd_pkts': 'Total Fwd Packets',
 'tot_bwd_pkts': 'Total Backward Packets',
 'totlen_fwd_pkts': 'Total Length of Fwd Packets',
 'totlen_bwd_pkts': 'Total Length of Bwd Packets',
 'fwd_pkt_len_max': 'Fwd Packet Length Max',
 'protocol': 'Fwd Header Length.1',
 'fwd_pkt_len_mean': 'Fwd Packet Length Mean',
 'fwd_pkt_len_std': 'Fwd Packet Length Std',
 'bwd_pkt_len_max': 'Bwd Packet Length Max',
 'bwd_pkt_len_min': 'Bwd Packet Length Min',
 'bwd_pkt_len_mean': 'Bwd Packet Length Mean',
 'bwd_pkt_len_std': 'Bwd Packet Length Std',
 'flow_byts_s': 'Flow Bytes/s',
 'flow_pkts_s': 'Flow Packets/s',
 'fwd_iat_tot': 'Fwd IAT Total',
 'bwd_iat_tot': 'Bwd IAT Total',
 'fwd_header_len': 'Fwd Header Length',
 'bwd_header_len': 'Bwd Header Length',
 'fwd_pkts_s': 'Fwd Packets/s',
 'bwd_pkts_s': 'Bwd Packets/s',
 'pkt_len_min': 'Min Packet Length',
 'pkt_len_max': 'Max Packet Length',
 'pkt_len_mean': 'Packet Length Mean',
 'pkt_len_std': 'Packet Length Std',
 'pkt_len_var': 'Packet Length Variance',
 'fin_flag_cnt': 'FIN Flag Count',
 'syn_flag_cnt': 'SYN Flag Count',
 'rst_flag_cnt': 'RST Flag Count',
 'psh_flag_cnt': 'PSH Flag Count',
 'ack_flag_cnt': 'ACK Flag Count',
 'urg_flag_cnt': 'URG Flag Count',
 'ece_flag_cnt': 'ECE Flag Count',
 'down_up_ratio': 'Down/Up Ratio',
 'pkt_size_avg': 'Average Packet Size',
 'subflow_fwd_pkts': 'Subflow Fwd Packets',
 'subflow_fwd_byts': 'Subflow Fwd Bytes',
 'subflow_bwd_pkts': 'Subflow Bwd Packets',
 'subflow_bwd_byts': 'Subflow Bwd Bytes',
 'init_fwd_win_byts': 'Init_Win_bytes_forward',
 'init_bwd_win_byts': 'Init_Win_bytes_backward',
 'fwd_seg_size_avg': 'Avg Fwd Segment Size',
 'bwd_seg_size_avg': 'Avg Bwd Segment Size',
 'fwd_seg_size_min': 'min_seg_size_forward',
 'fwd_byts_b_avg': 'Fwd Avg Bytes/Bulk',
 'fwd_pkts_b_avg': 'Fwd Avg Packets/Bulk',
 'fwd_blk_rate_avg': 'Fwd Avg Bulk Rate',
 'bwd_byts_b_avg': 'Bwd Avg Bytes/Bulk',
 'bwd_pkts_b_avg': 'Bwd Avg Packets/Bulk',
 'bwd_blk_rate_avg': 'Bwd Avg Bulk Rate',
 'fwd_act_data_pkts': 'act_data_pkt_fwd',
 'fwd_pkt_len_min': 'Fwd Packet Length Min',
 'dst_port': 'Destination Port'}


# Load in the real-time data from CSV
data = pd.read_csv('./CICIDS2017.csv')

# Define a function to run the model on the real-time data
def run_model(data):
    # Process the data and extract the relevant columns

    processed_data = process_data(data)
    # Run the model on the processed data
    results = model.predict_proba(processed_data)
    # Return the results
    return results

# Define a function to plot the detection history
def plot_history(data):
    # Process the data and extract the relevant columns
    processed_data = process_data(data)
    # Run the model on the processed data
    results = model.predict(processed_data)
    # Get the count of benign and malicious detections
    count = pd.Series(results).value_counts()
    # Plot the count in a bar plot
    fig, ax = plt.subplots()
    sns.barplot(x=count.index, y=count.values, ax=ax)
    ax.set_title('Detection History')
    ax.set_xlabel('Detection Result')
    ax.set_ylabel('Count')
    return fig

# Define a function to process the data before feeding it to the model
def process_data(data):
    # Preprocess the data as needed (e.g., one-hot encode categorical variables)
    try:
        processed_data = data.rename(columns=rename_cols)[TRAIN_COLS].values
    except Exception as e:
        process_data = data[TRAIN_COLS].values
    return processed_data

# Set up the Streamlit app layout
st.title('Real-time Intrusion Detection System')
st.subheader('Live Detections')
st.markdown('This section displays the most recent detections from the IDS.')

# Run the model on the latest data and display the results
latest_data = data.head(1)
results = run_model(latest_data)
LBL = label_encoder.inverse_transform([results.argmax()])[0]
if results.argmax() == 0:
    st.success(f'No intrusion detected.  Normal Packed by  {results*100:.4f}%')
else:
    # st.error(results)

    st.error(f'Intrusion detected with score: {round(results.max() * 100, 2)}%   as  {LBL}')

st.subheader('Detection History')
st.markdown('This section displays a history of detections over time.')

# Plot the detection history
fig = plot_history(data)
st.pyplot(fig)

# st.subheader('Model Inputs')
# st.markdown('This section displays the inputs used by the model.')

# Display the TRAIN_COLS variable and the latest data as a table
# st.write('**Model Columns:**')
# st.write(TRAIN_COLS)
st.write('**Latest Data:**')
st.write(latest_data)
