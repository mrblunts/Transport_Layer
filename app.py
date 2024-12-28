import streamlit as st
import pandas as pd

# Assuming packet_data is a DataFrame containing your packet data
packet_data = pd.DataFrame({
    'Protocol': ['TCP', 'UDP', 'TCP', 'ICMP'],
    'Source': ['192.168.1.1', '192.168.1.2', '192.168.1.3', '192.168.1.4'],
    'Destination': ['192.168.1.5', '192.168.1.6', '192.168.1.7', '192.168.1.8'],
    'Length': [60, 70, 80, 90]
})

# Streamlit app
st.title('Network Traffic Monitor')

# Home page
st.header('Home')
if st.button('Stop Sniffing'):
    # Implement your stop_sniffing logic here
    st.write('Sniffing stopped.')

# Filter packets
st.header('Filter Packets')
protocol = st.selectbox('Select Protocol', packet_data['Protocol'].unique())
filtered_data = packet_data[packet_data['Protocol'] == protocol]
st.write(filtered_data)

# Display traffic chart
st.header('Traffic by Protocol')
st.image('static/traffic_chart.png', caption='Traffic Chart')

# Display recent packets table
st.header('Recent Packets')
st.write(packet_data)