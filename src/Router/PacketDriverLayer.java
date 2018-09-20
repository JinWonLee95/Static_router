package Router;

import java.io.File;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;

public class PacketDriverLayer extends BaseLayer {
   static {
      try {
         System.load(new File("jnetpcap.dll").getAbsolutePath());
         System.out.println(new File("jnetpcap.dll").getAbsolutePath());
      } catch (UnsatisfiedLinkError e) {
         System.out.println("Native code library failed to load.\n" + e);
         System.exit(1);
      }
   }

   int iNumberAdapter; // 어답터에 번호를 부여하기 위한 변수
   public Pcap adapterObject; // adapter 하나
   public PcapIf device;
   public ArrayList<PcapIf> adapterList;
   StringBuilder errorBuffer = new StringBuilder(); // 에러 메세지 생성
   long start; // 시작 시간

   /* 생성자 초기화용 */
   public PacketDriverLayer(String layerName) {
      super(layerName);

      adapterList = new ArrayList<PcapIf>();
      iNumberAdapter = 0;
      setAdapterList();

   }

   public void packetStartDriver() {
      int snaplength = 64 * 1024;
      int flags = Pcap.MODE_PROMISCUOUS;
      int timeout = 1 * 1000;

      adapterObject = Pcap.openLive(adapterList.get(iNumberAdapter).getName(), snaplength, flags, timeout,
            errorBuffer);

   }

   /* adapter에 번호 부여 */
   public void setAdapterNumber(int iNumber) {
      iNumberAdapter = iNumber;
      packetStartDriver();
      receive();
   }
   
   /* 연결된 adapter 읽어오기 */
   public void setAdapterList() {
         int r = Pcap.findAllDevs(adapterList, errorBuffer);

      if (r == Pcap.NOT_OK || adapterList.isEmpty())
         System.out.println("[Error] 네트워크 어댑터를 읽지 못하였습니다. Error : " + errorBuffer.toString());
   }
   
   /* 연결된 adapter들을 저장해줄 리스트 */
   public ArrayList<PcapIf> getAdapterList() {
      return adapterList;
   }

   /* 데이터 전송 */
   boolean send(byte[] data, int length) {
      ByteBuffer buffer = ByteBuffer.wrap(data); // data로 바이트 버퍼 생성
      start = System.currentTimeMillis(); // 현재 시간 저장 (시작시간)
      
      /* 어뎁터가 패킷 전송에 실패 했을 경우 */
      if (adapterObject.sendPacket(buffer) != Pcap.OK) {
         System.err.println(adapterObject.getErr());
         return false;
      }
      return true;
   }

   /* 데이터 수신 */
   synchronized boolean receive() {
      Receive_Thread thread = new Receive_Thread(adapterObject, (EthernetLayer) this.getUpperLayer()); // Receive_Thread에 있음
      Thread object = new Thread(thread);
      object.start(); // 쓰레드 시작
      try {
         object.join(1); // 현재 쓰레드가 동작 중이면 동작이 끝날 때 까지 기다림
      } catch (InterruptedException e) {
         // TODO Auto-generated catch block
         e.printStackTrace();
      }

      return false;
   }

   String[] getNICDescription() {
      String[] descriptionArray = new String[adapterList.size()];

      for (int i = 0; i < adapterList.size(); i++)
         descriptionArray[i] = adapterList.get(i).getDescription(); //adapter 하나씩 description(설명?)을 저장

      return descriptionArray;
   }
}

class Receive_Thread implements Runnable {
   byte[] data;
   Pcap adapterObejct;
   EthernetLayer upperLayer;

   /* 쓰레드 설정 함수 */
   public Receive_Thread(Pcap adapterObject, EthernetLayer upperLayer) {
      this.adapterObejct = adapterObject;
      this.upperLayer = upperLayer;
   }

   @Override
   public void run() {
      while (true) {
         PcapPacketHandler<String> packetHandler = new PcapPacketHandler<String>() {
            public void nextPacket(PcapPacket packet, String user) {
               data = packet.getByteArray(0, packet.size());
               
               // 아래 조건 만족 시 upperLayer에서 데이터 받아옴
               if ((data[12] == 8 && data[13] == 0) || (data[12] == 8 && data[13] == 6))
                  upperLayer.receive(data);
            }
         };
         adapterObejct.loop(1000, packetHandler, "");
      }
   }
}