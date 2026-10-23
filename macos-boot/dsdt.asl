DefinitionBlock ("", "DSDT", 2, "APPLE ", "F86DSDT", 0x00010000)
{
    Scope (\_PR)
    {
        Processor (CPU0, 0x00, 0x00000410, 0x06)
        {
            Name (_HID, "ACPI0007")
            Name (_UID, Zero)
            Method (_STA, 0, NotSerialized)
            {
                Return (0x0F)
            }
        }
    }
    Method (_PIC, 1, NotSerialized)
    {
    }
    Name (_S0, Package (0x04) { Zero, Zero, Zero, Zero })
    Name (_S5, Package (0x04) { 0x07, 0x07, Zero, Zero })
    Scope (_SB)
    {
        Device (PCI0)
        {
            Name (_HID, EisaId ("PNP0A08") /* PCI Express Bus */)
            Name (_CID, EisaId ("PNP0A03") /* PCI Bus */)
            Name (_UID, Zero)
            Name (_ADR, Zero)
            Name (_BBN, Zero)
            Method (_STA, 0, NotSerialized)
            {
                Return (0x0F)
            }
            Name (_CRS, ResourceTemplate ()
            {
                WordBusNumber (ResourceProducer, MinFixed, MaxFixed, PosDecode,
                    0x0000, 0x0000, 0x00FF, 0x0000, 0x0100, )
                IO (Decode16, 0x0CF8, 0x0CF8, 0x01, 0x08, )
                WordIO (ResourceProducer, MinFixed, MaxFixed, PosDecode, EntireRange,
                    0x0000, 0x0000, 0x0CF7, 0x0000, 0x0CF8, )
                WordIO (ResourceProducer, MinFixed, MaxFixed, PosDecode, EntireRange,
                    0x0000, 0x0D00, 0xFFFF, 0x0000, 0xF300, )
                DWordMemory (ResourceProducer, PosDecode, MinFixed, MaxFixed, Cacheable, ReadWrite,
                    0x00000000, 0x000A0000, 0x000BFFFF, 0x00000000, 0x00020000, )
                DWordMemory (ResourceProducer, PosDecode, MinFixed, MaxFixed, NonCacheable, ReadWrite,
                    0x00000000, 0x80000000, 0xFEBFFFFF, 0x00000000, 0x7EC00000, )
            })
            Device (LPC)
            {
                Name (_ADR, 0x001F0000)
                Device (PIC)
                {
                    Name (_HID, EisaId ("PNP0000"))
                    Name (_CRS, ResourceTemplate ()
                    {
                        IO (Decode16, 0x0020, 0x0020, 0x01, 0x02, )
                        IO (Decode16, 0x00A0, 0x00A0, 0x01, 0x02, )
                    })
                }
                Device (TIMR)
                {
                    Name (_HID, EisaId ("PNP0100"))
                    Name (_CRS, ResourceTemplate ()
                    {
                        IO (Decode16, 0x0040, 0x0040, 0x01, 0x04, )
                        IRQNoFlags () {0}
                    })
                }
                Device (HPET)
                {
                    Name (_HID, EisaId ("PNP0103"))
                    Name (_UID, Zero)
                    Name (_CRS, ResourceTemplate ()
                    {
                        Memory32Fixed (ReadWrite, 0xFED00000, 0x00000400, )
                    })
                    Method (_STA, 0, NotSerialized)
                    {
                        Return (0x0F)
                    }
                }
                Device (RTC)
                {
                    Name (_HID, EisaId ("PNP0B00"))
                    Name (_CRS, ResourceTemplate ()
                    {
                        IO (Decode16, 0x0070, 0x0070, 0x01, 0x08, )
                    })
                }
            }
        }
        Device (PNLF)
        {
            Name (_HID, EisaId ("APP0002"))
            Name (_CID, "backlight")
            Name (_UID, 0x0A)
            Method (_STA, 0, NotSerialized)
            {
                Return (0x0B)
            }
        }
    }
}
