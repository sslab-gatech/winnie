#pragma once

// Contained reverse-engineered headers for source engine structs and classes.

typedef void* (*CreateInterfaceFn)(const char *pName, int *pReturnCode);
class IDedicatedExports;
class IMemAlloc
{
public:
	virtual void *Alloc(size_t nSize, const char *pFileName, int nLine) = 0;
	virtual void *Alloc(size_t nSize) = 0;
	virtual void *Realloc(void *pMem, size_t nSize, const char *pFileName, int nLine) = 0;
	virtual void *Realloc(void *pMem, size_t nSize) = 0;
};

typedef void(*RunServerFn)(void);
RunServerFn pRunServer;

typedef void *(__thiscall *AllocFn)(IMemAlloc* pThis, size_t nSize);
AllocFn pAlloc;

typedef void(*pMsg_t)(const char*, ...);
pMsg_t pMsg;

class CModelInfoClient
{
public:
	virtual int ctor(char) = 0;
	virtual void sub_10233A40(int) = 0;
	virtual void sub_102334A0(int) = 0;
	virtual int GetModelName(int) = 0;
	virtual int GetVCollide_index(int, int) = 0;
	virtual int GetVCollide(int, int) = 0;
	virtual void sub_10233150() = 0;
	virtual void sub_10233080() = 0;
	virtual void sub_10232810() = 0;
	virtual void GetModelRenderBounds() = 0;
	virtual void ModelFrameCount() = 0;
	virtual void sub_10232A90() = 0;
	virtual void GetModelExtraData() = 0;
	virtual void sub_10232BE0() = 0;
	virtual void sub_10232C00() = 0;
	virtual void sub_10232D40() = 0;
	virtual void nullsub_1() = 0;
	virtual void sub_10232EB0() = 0;
	virtual void sub_10232EE0() = 0;
	virtual void sub_10232F00() = 0;
	virtual void sub_10232C20() = 0;
	virtual void sub_10233170() = 0;
	virtual void sub_102332A0() = 0;
	virtual void sub_10233390() = 0;
	virtual void sub_10232B10() = 0;
	virtual void* FindModel(void* pStudioHdr, void **cache, char *modelname) = 0;
	virtual void sub_10232B20() = 0;
	virtual void sub_10232B50() = 0;
	virtual void sub_10232B80() = 0;
	virtual void sub_10233D10() = 0;
	virtual void sub_10232F30() = 0;
	virtual void sub_10232F80() = 0;
	virtual void sub_102333B0() = 0;
	virtual void sub_102329F0() = 0;
	virtual void sub_10232A10() = 0;
	virtual void sub_10233AA0() = 0;
	virtual void sub_10233B00() = 0;
	virtual void sub_10233B20() = 0;
	virtual void sub_10233C50() = 0;
	virtual void sub_10233C70() = 0;
	virtual void sub_10232BB0() = 0;
	virtual void sub_102333E0() = 0;
	virtual void sub_10232D60() = 0;
	virtual void sub_102327A0() = 0;
	virtual void sub_10232710() = 0;
	virtual void sub_10233410() = 0;
	virtual void sub_10233440() = 0;
	virtual void sub_102326F0() = 0;
	virtual void sub_10232C40() = 0;
	virtual void sub_10232C70() = 0;
	virtual void sub_10233FA0() = 0;
	virtual void sub_10234050() = 0;
	virtual void sub_102340F0() = 0;
	virtual void sub_10234120() = 0;
	virtual void sub_102341B0() = 0;
	virtual void sub_102341E0() = 0;
	virtual void sub_10234210() = 0;
	virtual void sub_102336F0() = 0;
	virtual void sub_10233730() = 0;
	virtual void sub_10233770() = 0;
	virtual void sub_10233650() = 0;
	virtual void sub_102336A0() = 0;
	virtual void sub_102337B0() = 0;
	virtual void sub_102331C0() = 0;
	virtual void sub_102342F0() = 0;
	virtual void sub_10234310() = 0;
	virtual void sub_10233510() = 0;
	virtual void sub_10234250() = 0;
	virtual void sub_102342A0() = 0;
	virtual void sub_102342C0() = 0;
	virtual void sub_102342E0() = 0;
	virtual void sub_10233A30() = 0;
	virtual void sub_10233A70() = 0;
};

enum SearchPathAdd_t
{
	PATH_ADD_TO_HEAD,		// First path searched
	PATH_ADD_TO_TAIL,		// Last path searched
};

class IFileSystem
{
public:
	virtual void sub_100157E0() = 0;
	virtual void sub_100157A0() = 0;
	virtual void sub_1000A080() = 0;
	virtual void sub_1000A0F0() = 0;
	virtual void sub_1000A230() = 0;
	virtual void sub_10006460() = 0;
	virtual void sub_100157D0() = 0;
	virtual void sub_10006430() = 0;
	virtual void sub_10006080() = 0;
	virtual void pad0() = 0;
	virtual void pad1() = 0;
	virtual void AddSearchPath(const char *pPath, const char *pathID, SearchPathAdd_t addType) = 0;
	virtual void RemoveSearchPath(const char *pPath, const char *pathID) = 0;
	virtual void sub_1000EE20() = 0;
	virtual void sub_1000E420() = 0;
	virtual void sub_10014D80() = 0;
	virtual void sub_10008E80() = 0;
	virtual void sub_10013D50() = 0;
	virtual void sub_1000DBE0() = 0;
	virtual void sub_1000B080() = 0;
	virtual void sub_100142C0() = 0;
	virtual void sub_10014380() = 0;
	virtual void sub_100127C0() = 0;
	virtual void sub_10012450() = 0;
	virtual void sub_10011F60() = 0;
	virtual void sub_10010DE0() = 0;
	virtual void sub_10010E40() = 0;
	virtual void sub_100109A0() = 0;
	virtual void sub_10010F70() = 0;
	virtual void sub_10010D00() = 0;
	virtual void sub_10014A90() = 0;
	virtual void sub_10007280() = 0;
	virtual void sub_100137F0() = 0;
	virtual void sub_10013B00() = 0;
	virtual void sub_10013BC0() = 0;
	virtual void sub_10013BE0() = 0;
	virtual void sub_100131A0() = 0;
	virtual void sub_10012A60() = 0;
	virtual void sub_10014040() = 0;
	virtual void sub_100142A0() = 0;
	virtual void sub_10014530() = 0;
	virtual void sub_10014C80() = 0;
	virtual void sub_10014CA0() = 0;
	virtual void sub_10018CE0() = 0;
	virtual void sub_10008A90() = 0;
	virtual void sub_10019050() = 0;
	virtual void sub_10019130() = 0;
	virtual void sub_100191C0() = 0;
	virtual void sub_10019340() = 0;
	virtual void sub_10019200() = 0;
	virtual void sub_10019220() = 0;
	virtual void sub_10019240() = 0;
	virtual void sub_10006490() = 0;
	virtual void sub_10019260() = 0;
	virtual void sub_100192A0() = 0;
	virtual void sub_10019300() = 0;
	virtual void sub_10019320() = 0;
	virtual void sub_10019360() = 0;
	virtual void sub_100193B0() = 0;
	virtual void sub_100193D0() = 0;
	virtual void pad2() = 0;
	virtual void pad3() = 0;
	virtual void pad4() = 0;
	virtual void pad5() = 0;
	virtual void pad6() = 0;
	virtual void nullsub_2() = 0;
	virtual void sub_1000AC00() = 0;
	virtual void PrintSearchPaths() = 0;
	virtual void sub_10014590() = 0;
	virtual void sub_100145A0() = 0;
	virtual void sub_10014C00() = 0;
	virtual void sub_10014C20() = 0;
	virtual void sub_100145B0() = 0;
	virtual void sub_1000FB40() = 0;
	virtual void sub_100109F0() = 0;
	virtual void sub_1000E990() = 0;
	virtual void sub_10014C90() = 0;
	virtual void sub_10010B50() = 0;
	virtual void sub_10010B80() = 0;
	virtual void sub_10010AC0() = 0;
	virtual void sub_10010AF0() = 0;
	virtual void sub_10018E40() = 0;
	virtual void sub_10018F60() = 0;
	virtual void sub_10018D00() = 0;
	virtual void sub_100193F0() = 0;
	virtual void sub_10014E00() = 0;
	virtual void sub_1000E640() = 0;
	virtual void sub_1001A690() = 0;
	virtual void AllocOptimalReadBuffer() = 0;
	virtual void sub_1001A850() = 0;
	virtual void BeginMapAccess() = 0;
	virtual void EndMapAccess() = 0;
	virtual void sub_10014060() = 0;
	virtual void sub_10014CB0() = 0;
	virtual void sub_100112A0() = 0;
	virtual void sub_10008AB0() = 0;
	virtual void sub_10011950() = 0;
	virtual void sub_10011EB0() = 0;
	virtual void sub_100114E0() = 0;
	virtual void sub_100114F0() = 0;
	virtual void sub_10011940() = 0;
	virtual void sub_10011F40() = 0;
	virtual void sub_10009AD0() = 0;
	virtual void sub_10011F50() = 0;
	virtual void sub_1000A600() = 0;
	virtual void sub_10008AC0() = 0;
	virtual void sub_10008AD0() = 0;
	virtual void sub_10008AE0() = 0;
	virtual void sub_10008AF0() = 0;
	virtual void sub_1000DE10() = 0;
	virtual void sub_1000DBC0() = 0;
	virtual void sub_10008B00() = 0;
	virtual void sub_1000AC30() = 0;
	virtual void sub_1000AE90() = 0;
	virtual void sub_1000AFC0() = 0;
	virtual void sub_1000CB10() = 0;
	virtual void sub_1000DBD0() = 0;
	virtual void sub_10014F30() = 0;
	virtual void sub_10015270() = 0;
	virtual void sub_10006490_() = 0;
	virtual void sub_10014F30_() = 0;
	virtual void sub_10006460_() = 0;
	virtual void sub_10008A40() = 0;
	virtual void sub_100152D0() = 0;
	virtual void sub_10015280() = 0;
	virtual void sub_100153E0() = 0;
	virtual void sub_10008E80_() = 0;
	virtual void sub_10015470() = 0;
	virtual void sub_100119A0() = 0;
	virtual void sub_10011D60() = 0;
	virtual void sub_100145C0() = 0;
	virtual void sub_100146F0() = 0;
	virtual void sub_10014700() = 0;
	virtual void sub_1001A8C0() = 0;
	virtual void sub_1001A930() = 0;
	virtual void sub_1001A950() = 0;
	virtual void sub_1001A980() = 0;
	virtual void sub_1001A9C0() = 0;
	virtual void sub_1001A9D0() = 0;
	virtual void sub_1001A9E0() = 0;
	virtual void sub_1001AA00() = 0;
	virtual void sub_1001AA50() = 0;
	virtual void sub_1001AA70() = 0;
	virtual void sub_1001AA90() = 0;
	virtual void sub_1001AAB0() = 0;
	virtual void sub_1001AAC0() = 0;
	virtual void sub_1001AAD0() = 0;
	virtual void sub_1001AB20() = 0;
	virtual void sub_1001AAF0() = 0;
	virtual void sub_1001AB50() = 0;
	virtual void sub_1001AB60() = 0;
	virtual void sub_1001AB80() = 0;
	virtual void sub_1001ABA0() = 0;
	// 0x00 vtable
	char pad[0xa4]; // 0x04 pad
	int m_iMapLoad; // 0xa8 -- HARDCODED OFFSET
};

struct model_t;

// actually IModelLoader
class CModelLoader
{
public:
	enum REFERENCETYPE
	{
		// The name is allocated, but nothing else is in memory or being referenced
		FMODELLOADER_NOTLOADEDORREFERENCED = 0,
		// The model has been loaded into memory
		FMODELLOADER_LOADED = (1 << 0),

		// The model is being referenced by the server code
		FMODELLOADER_SERVER = (1 << 1),
		// The model is being referenced by the client code
		FMODELLOADER_CLIENT = (1 << 2),
		// The model is being referenced in the client .dll
		FMODELLOADER_CLIENTDLL = (1 << 3),
		// The model is being referenced by static props
		FMODELLOADER_STATICPROP = (1 << 4),
		// The model is a detail prop
		FMODELLOADER_DETAILPROP = (1 << 5),
		FMODELLOADER_REFERENCEMASK = (FMODELLOADER_SERVER | FMODELLOADER_CLIENT | FMODELLOADER_CLIENTDLL | FMODELLOADER_STATICPROP | FMODELLOADER_DETAILPROP),

		// The model was touched by the preload method
		FMODELLOADER_TOUCHED_BY_PRELOAD = (1 << 15),
		// The model was loaded by the preload method, a postload fixup is required
		FMODELLOADER_LOADED_BY_PRELOAD = (1 << 16),
		// The model touched its materials as part of its load
		FMODELLOADER_TOUCHED_MATERIALS = (1 << 17),
	};

	enum ReloadType_t
	{
		RELOAD_LOD_CHANGED = 0,
		RELOAD_EVERYTHING,
		RELOAD_REFRESH_MODELS,
	};

	virtual void Init() = 0;
	virtual void Shutdown() = 0;
	virtual void GetCount() = 0;
	virtual model_t* GetModelForIndex(int i) = 0;
	virtual const char* GetName(const model_t* model) = 0;
	virtual void* GetExtraData(model_t *model) = 0;
	virtual int GetModelFileSize(const char *name) = 0;
	virtual model_t	*GetModelForName(const char *name, REFERENCETYPE referencetype) = 0;
	virtual model_t	*ReferenceModel(const char *name, REFERENCETYPE referencetype) = 0;
	virtual void UnreferenceModel(model_t *model, REFERENCETYPE referencetype) = 0;
	virtual void UnreferenceAllModels(REFERENCETYPE referencetype) = 0;
	virtual void UnloadUnreferencedModels() = 0;
	virtual void PurgeUnusedModels() = 0;
	virtual void sub_1013CFD0() = 0;
	virtual void sub_1013CEA0() = 0;
	virtual void Map_GetRenderInfoAllocated() = 0;
	virtual void Map_SetRenderInfoAllocated() = 0;
	virtual void Map_LoadDisplacements() = 0;
	virtual void Print() = 0;
	virtual void Map_IsValid() = 0;
	virtual void RecomputeSurfaceFlags() = 0;
	virtual void Studio_ReloadModels(ReloadType_t reloadType) = 0;
	virtual void IsLoaded() = 0;
	virtual void sub_1013ED50() = 0;
	virtual void sub_1013ED60() = 0;
	virtual void sub_1013CC80() = 0;
	virtual void sub_101371E0() = 0;
	virtual void sub_101371F0() = 0;
	virtual void sub_101414C0() = 0;
	virtual void sub_101405A0() = 0;
	virtual void sub_10140660() = 0;
	virtual void sub_10140770() = 0;
	virtual void sub_10140820() = 0;
	virtual void sub_10140850() = 0;
	virtual void sub_10140C20() = 0;
	virtual void sub_10140CB0() = 0;
	virtual void sub_10140D80() = 0;
	virtual void sub_10140B30() = 0;
	virtual void sub_10140E60() = 0;
	virtual void sub_10141430() = 0;
	virtual void sub_1013F740() = 0;
	virtual void sub_1013F990() = 0;
	virtual void sub_1013F540() = 0;
	virtual void sub_1013F5E0() = 0;
	virtual void sub_1013F580() = 0;
};
