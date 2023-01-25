import java.net.URL;

import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.JPacketHandler;
import org.jnetpcap.JCaptureHeader;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapBpfProgram;
import org.jnetpcap.PcapIf;
import java.util.ArrayList;
import java.net.InetAddress;
import java.util.List;
import javax.swing.JOptionPane;

public class App {
    public static void main(String[] args) throws Exception {

        List<PcapIf> alldevs = new ArrayList<PcapIf>();
		StringBuilder errbuf = new StringBuilder();

        int r = Pcap.findAllDevs(alldevs, errbuf);
        System.out.println("Network devices found:");

		int i = 0;
		for (PcapIf device : alldevs) {
			System.out.printf("#%d: %s [%s]\n", i++, device.getName(), device
			    .getDescription());
		}
		int indx = Integer.parseInt(JOptionPane.showInputDialog(null, "choose a network device"));
        PcapIf device = alldevs.get(indx); 
		System.out.printf("\nChoosing '%s':\n", device
		    .getDescription());

        int snaplen = 64 * 1024; // Capture all packets, no trucation
        int flags = Pcap.MODE_PROMISCUOUS;//.MODE_NON_PROMISCUOUS;
        int timeout = 40 * 1000; // 40 seconds in millis    
        Pcap pcap = Pcap.openLive(device.getName(), snaplen, flags, timeout, errbuf);
		if (pcap == null) {
			System.err.printf("Error while opening device for capture: "
			    + errbuf.toString());
			return;
		}
		String googleaddress = "https://www.google.com/"; //"https://www.stackoverflow.com/"; 
        
        InetAddress googleip = InetAddress.getByName(new URL(googleaddress).getHost());
 
        System.out.println("Public IP Address of: " + googleip);
        char[] ch = googleip.toString().toCharArray();   //www.google.com/192.152.652.256
		Boolean booln = false;
		int c = 0;
		char[] ch02 = new char[ch.length-15];
		for (char s : ch) {
			if (s == '/') {
				booln = true;
				continue;
			}
			if(booln){
				ch02[c] = s;
				c++;
			}
		}
		String dstIp = String.copyValueOf(ch02);
		System.out.println("dst host " + dstIp);
		PcapBpfProgram capfilter = new PcapBpfProgram();
		String bpf = "dst host " + dstIp; //"dst host 172.217.16.196"; //443
		int bpfOptimize = 1;
		int netmask = 0;
		int compile = pcap.compile(capfilter, bpf, bpfOptimize, netmask);
		if(compile != pcap.OK){
			System.out.println("Filter error: "+ pcap.getErr());
		}
		pcap.setFilter(capfilter);
        

        JPacketHandler<String> jPacketHandler = new JPacketHandler<String>(){

            public void nextPacket(JPacket packet, String user) {
                final JCaptureHeader header = packet.getCaptureHeader();
				
				System.out.printf("Packet caplen=%d wirelen=%d\n", header.caplen(),
				    header.wirelen());

                System.out.println(packet.toString());
				System.out.println("**********************************************************************");
				
            }
        };
        pcap.loop(10, jPacketHandler, "jNetPcap");
        pcap.close();
    }

}
