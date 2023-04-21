import streamlit as st
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
import re
import os
import time

fig = None

# Set up Streamlit app title and icon
# st.set_page_config(page_title='Real-time IDS', page_icon=':shield:')

# Load in the trained model and the TRAIN_COLS variable
model = pd.read_pickle("rf_clf.pkl")


# load encoder
label_encoder = pd.read_pickle('encoder.pkl')
# TRAIN_COLS = ['src_ip', 'dst_ip', 'src_port', 'src_mac', 'dst_mac', 'timestamp']


from tester import rename_cols, TRAIN_COLS

# Define function to read CSV file
# @st.cache
def read_csv(file_path):
    data = pd.read_csv(file_path)
    return data

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


# Create inputs for selecting CSV file, network interface, and model type
file_mode = st.sidebar.selectbox('Select model type', ['uploader','live'])
print(f"\n\n {file_mode}")
if file_mode == "live":
    file_name = st.sidebar.text_input('Enter CSV filename', 'CICIDS2017.csv')
    network_interface = st.sidebar.selectbox('Select network interface', ['wlan0', 'eth0', 'lo'])
    model_type = st.sidebar.selectbox('Select model type', ['Sequence', 'Flow'])
else:
    # Allow users to upload a CSV file
    file_name = st.sidebar.file_uploader('Upload a CSV file', type='csv')

# if uploaded_file is not None:
#     # Load in the real-time data from CSV
#     data = pd.read_csv(uploaded_file)
#
#     try:
#         data.drop("predicted_label", inplace=True, axis=1)
#     except:
#         pass

def update_data_UI(file_name = file_name):
    # Set up the Streamlit app layout
    # Read the CSV file
    if not file_name:
        file_name = "CICIDS2017.csv"
    data = read_csv(file_name)


    # st.subheader('Model Inputs')
    # st.markdown('This section displays the inputs used by the model.')

    # Display the TRAIN_COLS variable and the latest data as a table
    # st.write('**Model Columns:**')
    # st.write(TRAIN_COLS)

    yield data
    time.sleep(30)



if fig:
    fig.clear()
data = next(update_data_UI())
# Initialize table with empty data
# table = st.empty()



while True:
    with st.empty():
        st.title('Real-time Intrusion Detection System')
        st.sidebar.title('Input Parameters')

        # Set up the main app layout
        st.subheader('Live Detections')
        st.markdown('This section displays the most recent detections from the IDS.')


        # Run the model on the latest data and display the results
        latest_data = data.sample(1)
        results = run_model(latest_data)
        LBL = label_encoder.inverse_transform([results.argmax()])[0]
        if results.argmax() == 0:
            st.success(f'No intrusion detected.  Normal Packed by  {round(results.max() * 100, 2)}%   as  {LBL}')
        else:
            # st.error(results)

            st.error(f'Intrusion detected with score: {round(results.max() * 100, 2)}%   as  {LBL}')

        st.subheader('Detection History')
        st.markdown('This section displays a history of detections over time.')

        st.metric(label="TOTAL ANALYSED", value=123, delta=123,delta_color="off")
        # Plot the detection history
        fig = plot_history(data)
        st.pyplot(fig)

        st.write('**Latest~ Data:**')
        # Wait for new data dictionary every 30 seconds
        # data_dict = data#next(data_gen)
        # Update table with new data
        st.dataframe(data)

    st.empty()
