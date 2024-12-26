from bt_ddos_shield.address import Address, AddressType, DefaultAddressSerializer


class TestAddress:
    """
    Test suite for the address.
    """

    def test_default_serializer(self):
        default_serializer = DefaultAddressSerializer()
        address: Address = Address(address_id='some_id', address_type=AddressType.DOMAIN, address='some_addr', port=80)
        serialized_address: bytes = default_serializer.serialize(address)
        deserialized_address: Address = default_serializer.deserialize(serialized_address)

        assert address == deserialized_address, "Deserialized data should match the original data"
