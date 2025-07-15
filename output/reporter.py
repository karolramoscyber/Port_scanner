
def report_results(protocol_label: str, open_ports: list[int], uncertain_ports: list[int]) -> None:
    """
    Display scan results in a readable format on the console.
    """
    if open_ports:
        print(f"[{protocol_label.upper()}] Open ports: {open_ports}")
    if uncertain_ports:
        print(f"[{protocol_label.upper()}] Possible filtered ports: {uncertain_ports}")
    if not open_ports and not uncertain_ports:
        print(f"[{protocol_label.upper()}] No open ports found.")