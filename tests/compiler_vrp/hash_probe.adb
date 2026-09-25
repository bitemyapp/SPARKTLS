with Ada.Text_IO; use Ada.Text_IO;
with Ada.Command_Line;
with Ada.Execution_Time;
with Ada.Real_Time; use Ada.Real_Time;
with Interfaces; use Interfaces;
with SPARKNaCl; use SPARKNaCl;
with SPARKNaCl.Hashing.SHA256;
with SPARKNaCl.Hashing.SHA512;
procedure Hash_Probe is
   use type Ada.Execution_Time.CPU_Time;
   type N32_Seq is array (Natural range <>) of N32;
   Hex : constant String := "0123456789abcdef";
   D : Bytes_32; E : Bytes_64;
   Seed : U32 := 16#12345678#;
   N : Natural := 0;
   procedure Print (X : Byte_Seq) is
   begin
      for B of X loop
         Put (Hex (Integer (B) / 16 + 1));
         Put (Hex (Integer (B) mod 16 + 1));
      end loop;
   end Print;
   procedure Check (Length : N32; Offset : N32; Pattern : Natural) is
      M : Byte_Seq (Offset .. Offset + Length - 1);
   begin
      for I in M'Range loop
         case Pattern is
            when 0 => M (I) := 0;
            when 1 => M (I) := 255;
            when 2 => M (I) := Byte ((I - Offset) mod 256);
            when others =>
               Seed := Seed xor Shift_Left (Seed, 13);
               Seed := Seed xor Shift_Right (Seed, 17);
               Seed := Seed xor Shift_Left (Seed, 5);
               M (I) := Byte (Seed and 255);
         end case;
      end loop;
      SPARKNaCl.Hashing.SHA256.Hash (D, M);
      SPARKNaCl.Hashing.SHA512.Hash (E, M);
      Put (N32'Image (Length) & " " & N32'Image (Offset) & " " &
           Natural'Image (Pattern) & " ");
      Print (D); Put (" "); Print (E); New_Line;
      N := N + 1;
   end Check;
begin
   if Ada.Command_Line.Argument_Count > 0 then
      declare
         Length : constant N32 := N32'Value (Ada.Command_Line.Argument (1));
         Count : constant Positive := Positive'Value (Ada.Command_Line.Argument (2));
         M : Byte_Seq (0 .. Length - 1) := (others => 7);
         T : Time;
         Elapsed : Duration;
         CPU_Start : Ada.Execution_Time.CPU_Time;
         CPU_Elapsed : Duration;
      begin
         for I in 1 .. 1000 loop
            SPARKNaCl.Hashing.SHA256.Hash (D, M);
            M (0) := D (0);
         end loop;
         T := Clock;
         CPU_Start := Ada.Execution_Time.Clock;
         for I in 1 .. Count loop
            SPARKNaCl.Hashing.SHA256.Hash (D, M);
            M (0) := D (0);
         end loop;
         CPU_Elapsed := To_Duration (Ada.Execution_Time.Clock - CPU_Start);
         Elapsed := To_Duration (Clock - T);
         Put (Duration'Image (Elapsed) & " " & Duration'Image (CPU_Elapsed) & " "); Print (D); New_Line;
      end;
   else
      for Pattern in 0 .. 3 loop
         for Offset of N32_Seq'(0, 1, 17, 4096, 2147400000) loop
            for Length in N32 range 0 .. 257 loop
               Check (Length, Offset, Pattern);
            end loop;
            for Length of N32_Seq'(511, 512, 513, 1023, 1024, 1025,
                                  2047, 2048, 2049, 4095, 4096, 4097,
                                  16383, 16384, 16385, 65535, 65536) loop
               Check (Length, Offset, Pattern);
            end loop;
         end loop;
      end loop;
      Put_Line (Standard_Error, "cases:" & Natural'Image (N));
   end if;
end Hash_Probe;
