import csv
from collections import defaultdict
from scapy.sendrecv import AsyncSniffer

from scapy.sessions import DefaultSession

from features.context.packet_direction import PacketDirection
from features.context.packet_flow_key import get_packet_flow_key
from flow import Flow

EXPIRED_UPDATE = 1
# MACHINE_LEARNING_API = "http://localhost:8000/predict"
GARBAGE_COLLECT_PACKETS = 100

FINAL_DATA =[]
import modeller



out_data= {}
class FlowSession(DefaultSession):
    """Creates a list of network flows."""

    def __init__(self, *args, **kwargs):
        self.GARBAGE_COLLECT_PACKETS = GARBAGE_COLLECT_PACKETS
        self.flows = {}
        self.csv_line = 0
        self.data_out ={}

        if self.output_mode == "flow":
            output = open(self.output_file, "w")
            self.csv_writer = csv.writer(output)

        self.packets_count = 0

        self.clumped_flows_per_label = defaultdict(list)

        super(FlowSession, self).__init__(*args, **kwargs)

    def toPacketList(self):
        # Sniffer finished all the packets it needed to sniff.
        # It is not a good place for this, we need to somehow define a finish signal for AsyncSniffer
        self.garbage_collect(None)
        return super(FlowSession, self).toPacketList()

    def on_packet_received(self, packet):
        count = 0
        direction = PacketDirection.FORWARD

        if self.output_mode != "flow":
            if "TCP" not in packet:
                return
            elif "UDP" not in packet:
                return

        try:
            # Creates a key variable to check
            packet_flow_key = get_packet_flow_key(packet, direction)
            flow = self.flows.get((packet_flow_key, count))
        except Exception:
            return

        self.packets_count += 1

        # If there is no forward flow with a count of 0
        if flow is None:
            # There might be one of it in reverse
            direction = PacketDirection.REVERSE
            packet_flow_key = get_packet_flow_key(packet, direction)
            flow = self.flows.get((packet_flow_key, count))

        if flow is None:
            # If no flow exists create a new flow
            direction = PacketDirection.FORWARD
            flow = Flow(packet, direction)
            packet_flow_key = get_packet_flow_key(packet, direction)
            self.flows[(packet_flow_key, count)] = flow

        elif (packet.time - flow.latest_timestamp) > EXPIRED_UPDATE:
            # If the packet exists in the flow but the packet is sent
            # after too much of a delay than it is a part of a new flow.
            expired = EXPIRED_UPDATE
            while (packet.time - flow.latest_timestamp) > expired:
                count += 1
                expired += EXPIRED_UPDATE
                flow = self.flows.get((packet_flow_key, count))

                if flow is None:
                    flow = Flow(packet, direction)
                    self.flows[(packet_flow_key, count)] = flow
                    break
        elif "F" in str(packet.flags):
            # If it has FIN flag then early collect flow and continue
            flow.add_packet(packet, direction)
            self.garbage_collect(packet.time)
            return

        flow.add_packet(packet, direction)

        if not self.url_model:
            self.GARBAGE_COLLECT_PACKETS = 10000

        if self.packets_count % self.GARBAGE_COLLECT_PACKETS == 0 or (
            flow.duration > 120 and self.output_mode == "flow"
        ):
            self.garbage_collect(packet.time)

    def get_flows(self) -> list:
        return self.flows.values()

    def garbage_collect(self, latest_time) -> None:
        # TODO: Garbage Collection / Feature Extraction should have a separate thread
        if not self.url_model:
            pass
            print("Packet Collection Began. Flows = {}".format(len(self.flows)))
        keys = list(self.flows.keys())
        for k in keys:
            flow = self.flows.get(k)
            if (
                latest_time is None
                or latest_time - flow.latest_timestamp > EXPIRED_UPDATE
                or flow.duration > 90
            ):

                data = flow.get_data()
                FINAL_DATA.append(data)
                print(f"Length Data is {len(FINAL_DATA)}")
                if self.csv_line == 0:
                    self.csv_writer.writerow(data.keys())

                self.csv_writer.writerow(data.values())
                self.csv_line += 1
                print('wrote')

                del self.flows[k]
        if not self.url_model:
            pass
#             print(out_data)
            print("Packet Collection Finished... Flows = {}".format(len(self.flows)))
#             result_modelled = modeller.main(self.data_out)
#             print(f"Results Predicted as  {result_modelled}")


def create_sniffer(
input_file, input_interface, output_mode, output_file, url_model=None
):
    assert (input_file is None) ^ (input_interface is None)

    NewFlowSession = generate_session_class(output_mode, output_file, url_model)

    if input_file is not None:
        return AsyncSniffer(
        offline=input_file,
        filter="ip and (tcp or udp)",
        prn=None,
        session=NewFlowSession,
        store=False,
        )
    else:
        return AsyncSniffer(
        iface=input_interface,
        filter="ip and (tcp or udp)",
        prn=None,
        session=NewFlowSession,
        store=False,
        )


def generate_session_class(output_mode, output_file, url_model):
    return type(
        "NewFlowSession",
        (FlowSession,),
        {
            "output_mode": output_mode,
            "output_file": output_file,
            "url_model": url_model,
        },
    )




if __name__ == "__main__":
    from scapy.sendrecv import AsyncSniffer
    from scapy.sendrecv import AsyncSniffer
    sniffer = create_sniffer(
        None,
        "wlan0",
        "flow",
        "DATA.csv",
        None#"http://127.0.0.1:8000/predictions"
    )
    sniffer.start()

    try:
        sniffer.join()
    except KeyboardInterrupt:
        sniffer.stop()
    finally:
        sniffer.join()
