import os
import json
import pandas as pd
import logging
import tkinter as tk
from pathlib import Path
from sklearn.ensemble import IsolationForest
from docx import Document
from datetime import datetime
from tkinter import filedialog
from tkinter import scrolledtext
from tkinter import messagebox
from sklearn.preprocessing import LabelEncoder

# Function to load logs from a directory
def load_logs(directory):
    logs = []
    for filename in os.listdir(directory):
        filepath = os.path.join(directory, filename)
        # Convert file to JSON
        if filename.endswith('.csv'):
            try:
                # Read file into Pandas DataFrame
                df = pd.read_csv(filepath)
                # Convert DataFrame into list of dictionaries
                csv_logs = df.to_dict(orient='records')
                logs.extend(csv_logs)
                logging.info(f"Successfully loaded and converted CSV file: {filename}")
            except Exception as e:
                logging.error(f"Error loading and processing CSV file {filename}: {e}")
    return logs


# Function to perform anomaly detection using Isolation Forest
def detect_anomalies(log_data):
    # Label encode the categorical columns (Event Type and Source IP)
    label_encoder = LabelEncoder()
    log_data['Event Type'] = label_encoder.fit_transform(log_data['Event Type'])
    log_data['Source IP'] = label_encoder.fit_transform(log_data['Source IP'])
    
    # Fit the Isolation Forest model
    model = IsolationForest(contamination=0.1)  # Adjust contamination level as needed
    log_data['anomaly'] = model.fit_predict(log_data[['Event Type', 'Source IP']])
    
    # Filter anomalies (marked as -1 by Isolation Forest)
    anomalies = log_data[log_data['anomaly'] == -1]
    return anomalies

# Function to generate a Word document report of the findings
def generate_report(anomalies, report_filename):
    document = Document()
    document.add_heading('Threat Hunting Report', 0)
    
    document.add_paragraph(f'Report generated on: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}')
    document.add_paragraph("The following anomalies were detected in the logs:\n")
    
    for _, anomaly in anomalies.iterrows():
        document.add_heading(f"Anomaly Event Name: {anomaly['Event Name']}", level=1)
        document.add_paragraph(f"Anomaly Event Type: {anomaly['Event Type']}")
        document.add_paragraph(f"Event Time Recieved: {anomaly['Event Receive Time']}")
        document.add_paragraph(f"Event Source IP: {anomaly['Source IP']}")
        document.add_paragraph(f"Event Destination IP: {anomaly['Destination IP']}")
        document.add_paragraph(f"Reason for Detection: Anomalous behavior detected based on event type and IP.")
        document.add_paragraph("Suggested Actions: Investigate the source of traffic. Block suspicious IP if necessary.\n")
    document.save(report_filename)

# GUI for application
class ThreatHuntingGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Threat Hunter 'OrioN'")
        frame = tk.Frame(root, bg = 'black')
        frame.place(relwidth=1, relheight=1)
        self.root.geometry("1920x1080")

        # Directory for logs
        self.log_directory = r"C:\Users\aeisa\Desktop\Log Directory"  # Default path, can be changed by user

        # GUI elements
        self.create_widgets()

    def create_widgets(self):
        # Load Label
        self.dir_label = tk.Label(self.root, text="No Directory Selected")
        self.dir_label.pack(pady=10)

        # Load log buttons
        self.load_button = tk.Button(self.root, text="Select Log Directory", command=self.load_log_directory)
        self.load_button.pack(pady=10)

        # Run threat hunting button
        self.run_button = tk.Button(self.root, text="Run OrioN", command=self.run_threat_hunting, bg='red', fg='white')
        self.run_button.pack(pady=10)

        # Results display area
        self.results_text = scrolledtext.ScrolledText(self.root, wrap=tk.WORD, width=100, height=40)
        self.results_text.pack(padx=10, pady=10)

        # Past reports
        self.past_reports_label = tk.Label(self.root, text="Past Generated Reports")
        self.past_reports_label.pack(pady=5)

        self.past_reports_listbox = tk.Listbox(self.root, width=80, height=5)
        self.past_reports_listbox.pack(padx=10, pady=5)

    def load_log_directory(self):
        directory = filedialog.askdirectory()
        if directory:
            self.log_directory = directory
            self.dir_label.config(text=f"Selected Directory: {self.log_directory}")
            self.load_button.config(state=tk.DISABLED)  # Disables button after loading
        else:
            messagebox.showwarning("No Directory", "No directory has been selected. Please select a valid directory.")

    def run_threat_hunting(self):
        if not self.log_directory:
            messagebox.showwarning("No Directory", "Please select a directory first.")
            return

        # Load and process logs
        logs = load_logs(self.log_directory)
        if not logs:
            messagebox.showwarning("No Logs", "No logs were found in the selected directory")
            return

        log_data = pd.DataFrame(logs)

        # Check for essential columns
        required_columns = ['Event Name', 'Event Receive Time', 'Source IP', 'Destination IP']
        missing_columns = [col for col in required_columns if col not in log_data.columns]
        
        if missing_columns:
            messagebox.showwarning("Missing Columns", f"Logs are missing necessary columns: {', '.join(missing_columns)}")
            return

        # Detect Anomalies
        anomalies = detect_anomalies(log_data)

        if anomalies.empty:
            messagebox.showinfo("No Anomalies", "No anomalies detected")
            self.results_text.delete(1.0, tk.END)
            self.results_text.insert(tk.END, "No anomalies detected.")
        else:
            # Display Findings
            self.results_text.delete(1.0, tk.END)
            self.results_text.insert(tk.END, f"Anomalies Detected: {len(anomalies)}\n\n")
            
            # Display Details
            for _, anomaly in anomalies.iterrows():
                self.results_text.insert(tk.END, f"Anomaly Event Name: {anomaly['Event Name']}\n")
                self.results_text.insert(tk.END, f"Anomaly Event Type: {anomaly['Event Type']}\n")
                self.results_text.insert(tk.END, f"Anomaly Event Time Received: {anomaly['Event Receive Time']}\n")
                self.results_text.insert(tk.END, f"Anomaly Event Source IP: {anomaly['Source IP']}\n")
                self.results_text.insert(tk.END, f"Anomaly Event Destination IP: {anomaly['Destination IP']}\n")  

            # Generate the report and add it to the list of past reports
            report_filename = f"threat_hunting_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.docx"
            generate_report(anomalies, report_filename)
            self.past_reports_listbox.insert(tk.END, report_filename)
            messagebox.showinfo("Report Generated", f"Report generated: {report_filename}")

# Main function to go through the threat hunting process
if __name__ == "__main__":
    root = tk.Tk()
    app = ThreatHuntingGUI(root)
    root.mainloop()
