use incomudon_protocol::{Packet, PacketHeader, PacketType};

#[test]
fn plain_packet_round_trip() {
    let packet = Packet::Plain {
        header: PacketHeader::new(PacketType::Ping, 111, 1002, 9),
        payload: vec![1, 2, 3, 4],
    };
    let encoded = packet.encode().unwrap();
    assert_eq!(Packet::decode(&encoded).unwrap(), packet);
}
