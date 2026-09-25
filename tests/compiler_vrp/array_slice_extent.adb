-- { dg-do run }
-- { dg-options "-O2 -gnatp" }

with Interfaces; use Interfaces;
procedure Array_Slice_Extent is
   type Bytes is array (Integer range <>) of Unsigned_8;
   subtype Four_Bytes is Bytes (0 .. 3);
   subtype Buffer_Type is Bytes (0 .. 31);
   type Words is array (0 .. 7) of Unsigned_32;

   function Unpack (Value : Unsigned_32) return Four_Bytes is
      Result : Four_Bytes;
      T : Unsigned_32 := Value;
   begin
      for I in reverse Result'Range loop
         pragma Loop_Optimize (No_Unroll);
         Result (I) := Unsigned_8 (T mod 256);
         T := Shift_Right (T, 8);
      end loop;
      return Result;
   end Unpack;

   procedure Serialize (Buffer : in out Buffer_Type; Input : Words) is
   begin
      for I in Input'Range loop
         pragma Loop_Optimize (No_Unroll);
         Buffer (4 * I .. 4 * I + 3) := Unpack (Input (I));
      end loop;
   end Serialize;
   pragma No_Inline (Serialize);

   Buffer : Buffer_Type := (others => 42);
   Input : Words := (others => 16#12345678#);
begin
   Serialize (Buffer, Input);
   -- The stores cover bytes 0..31, not merely bytes 0..28.  The upper
   -- bound on the starting index does not bound the entire slice.
   if Buffer (29) /= 16#34#
     or else Buffer (30) /= 16#56#
     or else Buffer (31) /= 16#78#
   then
      raise Program_Error;
   end if;
end Array_Slice_Extent;
