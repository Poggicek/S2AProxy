#include <sourcemod>
#include <sdktools>
#include <dhooks>
#pragma newdecls required
#pragma semicolon 1

int g_platform;

public Plugin myinfo =
{
	name = "S2AProxy",
	author = "Poggu",
	description = "Detours NET_SendPacket to tamper with S2A responses",
	version = "1.0.1"
};

GlobalForward g_ExcludeForward;
GlobalForward g_ExcludeCountForward;

public void OnPluginStart()
{
  GameData hGameConf;
  char error[128];

  hGameConf = LoadGameConfigFile("s2aproxy.games");
  if(!hGameConf)
  {
    Format(error, sizeof(error), "Failed to find s2aproxy.games");
    SetFailState(error);
  }

  g_platform = hGameConf.GetOffset("WindowsOrLinux");

  Handle hNetSendPacket = DHookCreateDetour(Address_Null, CallConv_CDECL, ReturnType_Int, ThisPointer_Ignore);
  if (!hNetSendPacket)
    SetFailState("Failed to setup detour for NET_SendPacket");

  if (!DHookSetFromConf(hNetSendPacket, hGameConf, SDKConf_Signature, "NET_SendPacket"))
    SetFailState("Failed to load NET_SendPacket signature from gamedata");


  if(g_platform == 1)
  {
    DHookAddParam(hNetSendPacket, HookParamType_Int, .custom_register=DHookRegister_ECX);
    DHookAddParam(hNetSendPacket, HookParamType_ObjectPtr, -1, .custom_register=DHookRegister_EDX); // Windows call convention
  }
  else
  {
    DHookAddParam(hNetSendPacket, HookParamType_Int);
    //DHookAddParam(hNetSendPacket, HookParamType_ObjectPtr, -1, DHookPass_ByRef);
    DHookAddParam(hNetSendPacket, HookParamType_Int);
  }
  DHookAddParam(hNetSendPacket, HookParamType_Int);
  DHookAddParam(hNetSendPacket, HookParamType_Int);
  DHookAddParam(hNetSendPacket, HookParamType_Int);

  if (!DHookEnableDetour(hNetSendPacket, false, Detour_OnNetSendPacket))
      SetFailState("Failed to detour NET_SendPacket.");

  delete hGameConf;

  g_ExcludeForward = new GlobalForward("OnClientPlayerList", ET_Event, Param_String);
  g_ExcludeCountForward = new GlobalForward("OnServerExcludeCount", ET_Event, Param_CellByRef);
}

public APLRes AskPluginLoad2(Handle plugin, bool late, char[] error, int err_max)
{
    RegPluginLibrary("S2AProxy");
}

int GetInfoPlayersIndex(const char[] bytes)
{
  int cursor = 6; // Skip header + protocol;
  int strings;

  do
  {
    if(bytes[cursor] == '\0')
      strings++;

    cursor++;
  } while(strings < 4);

  cursor += 2; // Skip ID;
  return cursor;
}

int RetrieveData(const char[] bytes, char[] out, int length)
{
  int cursor = 5; // skip header
  int outCursor;
  int players = bytes[cursor];
  int outPlayers;

  // New header
  out[0] = 0xFF;
  out[1] = 0xFF;
  out[2] = 0xFF;
  out[3] = 0xFF;
  out[4] = 0x44;
  out[5] = players;
  outCursor += 6;

  cursor++; // skip player count
  while(cursor < length)
  {
    char name[MAX_NAME_LENGTH];
    int nameLength;

    while(bytes[cursor + 1 + nameLength] != '\0')
    {
      name[nameLength] = bytes[cursor + 1 + nameLength];
      nameLength++;
    }

    // Expose forward for other plugins to exclude players

    Action result;
    Call_StartForward(g_ExcludeForward);
    Call_PushString(name);
    Call_Finish(result);

    if(result == Plugin_Handled || result == Plugin_Stop)
    {
      // cursor is the cursor that goes through the bytes of the original data
      // we have to make sure we skip all the data related to the skipped player so our outCursor and cursor don't go out of sync wreck all the data
      cursor += nameLength + 1 + 1 + 4 + 4; // Skip name + null, id, skip duration, skip score
      continue;
    }

    outPlayers++;
    nameLength = 0;

    out[outCursor] = bytes[cursor];
    cursor++; // skip id
    outCursor++;

    while(bytes[cursor + nameLength] != '\0')
    {
      out[outCursor + nameLength] = bytes[cursor + nameLength];
      nameLength++;
    }

    cursor += nameLength + 1; // skip name + null
    outCursor += nameLength + 1;

    out[outCursor] = bytes[cursor];
    out[outCursor + 1] = bytes[cursor + 1];
    out[outCursor + 2] = bytes[cursor + 2];
    out[outCursor + 3] = bytes[cursor + 3];
    cursor += 4; // skip score
    outCursor += 4;

    out[outCursor] = bytes[cursor];
    out[outCursor + 1] = bytes[cursor + 1];
    out[outCursor + 2] = bytes[cursor + 2];
    out[outCursor + 3] = bytes[cursor + 3];
    cursor += 4; // skip duration
    outCursor += 4;
  }

  out[5] = outPlayers; // Update players field
  return outCursor;
}

public MRESReturn Detour_OnNetSendPacket(Handle hReturn, Handle hParams)
{
  Address strAddress = DHookGetParam(hParams, 3);
  int size = DHookGetParam(hParams, 4);

  if(size <= 4)
  {
    PrintToServer("[S2AProxy - ERROR] size smaller than 4");
    return MRES_Ignored;
  }

  char bytes[2048];
  int packetHeader = LoadFromAddress(strAddress + view_as<Address>(4), NumberType_Int8);

  if(packetHeader != 0x44 && packetHeader != 0x49)
    return MRES_Ignored;

  for(int i = 0; i < size; i++)
  {
    int val = LoadFromAddress(strAddress + view_as<Address>(i), NumberType_Int8);
    bytes[i] = val;
  }

  if(packetHeader == 0x44) // A2S_PLAYER
  {
    char newData[2048];
    int newSize = RetrieveData(bytes, newData, size);
    for(int i = 0; i < newSize; i++)
    {
      StoreToAddress(strAddress + view_as<Address>(i), newData[i], NumberType_Int8);
    }
    DHookSetParam(hParams, 4, newSize);
  }
  else if(packetHeader == 0x49) // A2S_INFO
  {
    int playersIndex = GetInfoPlayersIndex(bytes);
    int playerCount = LoadFromAddress(strAddress + view_as<Address>(playersIndex), NumberType_Int8);
    int excludeCount = 0;

    Action result;
    Call_StartForward(g_ExcludeCountForward);
    Call_PushCellRef(excludeCount);
    Call_Finish(result);

    if(excludeCount < 0)
      excludeCount = 0;

    if(excludeCount > playerCount)
      excludeCount = playerCount;

    if(result == Plugin_Changed)
      StoreToAddress(strAddress + view_as<Address>(playersIndex), playerCount - excludeCount, NumberType_Int8);
  }
  return MRES_ChangedHandled;
}