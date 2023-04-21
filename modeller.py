# get the columns to be renamed

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



# training columns


# training columns
train_cols =['Destination Port', 'Flow Duration', 'Total Fwd Packets',
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



import os,re
import pandas as pd
import numpy as np

# function to get results
def get_model_results(data_dict, model, label_encoder):
    #convert all the data into a dataframe
    curr_data = pd.DataFrame(data_dict, index=[0])
    
    #get basic information i.e destination and source ip and mac address, timestamp
    basic_info = curr_data[['src_ip', 'dst_ip', 'src_port', 'src_mac', 'dst_mac', 'timestamp']]
    
    #get the information into values to be used for modelling and predict the results
    model_pred = model.predict_proba(
        curr_data.rename(columns=rename_cols)[train_cols].values
    )
    
    #get back the model prediction and percentage predicted
    return label_encoder.inverse_transform([model_pred.argmax()])[0], model_pred.max()



# create main
def main(sample_data):
    # load the model
    rf_clf = pd.read_pickle("./rf_clf.pkl")
    lbl_encoder = pd.read_pickle("./encoder.pkl")
    
    results = get_model_results(sample_data, rf_clf, lbl_encoder)
    return (results)
    
    
# sample data
sample_data = {'src_ip': '127.0.0.1', 'dst_ip': '127.0.0.1', 'src_port': 42288, 'dst_port': 53, 'src_mac': '00:00:00:00:00:00', 'dst_mac': '00:00:00:00:00:00', 'protocol': 17, 'timestamp': '2023-01-19 21:10:02', 'flow_duration': 0.95367431640625, 'flow_byts_s': 157286400.0, 'flow_pkts_s': 2097152.0, 'fwd_pkts_s': 2097152.0, 'bwd_pkts_s': 0.0, 'tot_fwd_pkts': 2, 'tot_bwd_pkts': 0, 'totlen_fwd_pkts': 150, 'totlen_bwd_pkts': 0, 'fwd_pkt_len_max': 75.0, 'fwd_pkt_len_min': 75.0, 'fwd_pkt_len_mean': 75.0, 'fwd_pkt_len_std': 0.0, 'bwd_pkt_len_max': 0.0, 'bwd_pkt_len_min': 0.0, 'bwd_pkt_len_mean': 0.0, 'bwd_pkt_len_std': 0.0, 'pkt_len_max': 75, 'pkt_len_min': 75, 'pkt_len_mean': 75.0, 'pkt_len_std': 0.0, 'pkt_len_var': 0.0, 'fwd_header_len': 16, 'bwd_header_len': 0, 'fwd_seg_size_min': 8, 'fwd_act_data_pkts': 2, 'flow_iat_mean': 0.0, 'flow_iat_max': 0.0, 'flow_iat_min': 0.0, 'flow_iat_std': 0.0, 'fwd_iat_tot': 0, 'fwd_iat_max': 0.0, 'fwd_iat_min': 0.0, 'fwd_iat_mean': 0.0, 'fwd_iat_std': 0.0, 'bwd_iat_tot': 0.0, 'bwd_iat_max': 0.0, 'bwd_iat_min': 0.0, 'bwd_iat_mean': 0.0, 'bwd_iat_std': 0.0, 'fwd_psh_flags': 0, 'bwd_psh_flags': 0, 'fwd_urg_flags': 0, 'bwd_urg_flags': 0, 'fin_flag_cnt': 1, 'syn_flag_cnt': 0, 'rst_flag_cnt': 0, 'psh_flag_cnt': 0, 'ack_flag_cnt': 0, 'urg_flag_cnt': 0, 'ece_flag_cnt': 0, 'down_up_ratio': 0.0, 'pkt_size_avg': 75.0, 'init_fwd_win_byts': 0, 'init_bwd_win_byts': 0, 'active_max': 0.0, 'active_min': 0.0, 'active_mean': 0.0, 'active_std': 0.0, 'idle_max': 0.0, 'idle_min': 0.0, 'idle_mean': 0.0, 'idle_std': 0.0, 'fwd_byts_b_avg': 0.0, 'fwd_pkts_b_avg': 0.0, 'bwd_byts_b_avg': 0.0, 'bwd_pkts_b_avg': 0.0, 'fwd_blk_rate_avg': 0.0, 'bwd_blk_rate_avg': 0.0, 'fwd_seg_size_avg': 75.0, 'bwd_seg_size_avg': 0.0, 'cwe_flag_count': 0, 'subflow_fwd_pkts': 2, 'subflow_bwd_pkts': 0, 'subflow_fwd_byts': 150, 'subflow_bwd_byts': 0}


if __name__ == "__main__":
    print(main(sample_data))
    
    
    
