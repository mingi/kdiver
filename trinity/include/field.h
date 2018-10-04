#pragma once

#define u8 unsigned char

u32 get_values(char* values, u8*** pdest, int size);
struct st_field** read_field_file(u8* field_file, u32* pfield_count);
 
//struct st_field** fields;

struct st_field{
  u32 start;
  u32 size;
  u32 type;
  u32 value_count;
  u32 marker_count;
  u32 constraint_count;
  u32 interest_count;
  u64* values;
  u8** markers;
  u8** constraints;
  u8** interests;
};

void start_taint();
void reset_taint();
void stop_taint();