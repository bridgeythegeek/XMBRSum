///////////////////////////////////////////////////////////////////////////////
// X-Tension API - Implementation of XT_RetrieveFunctionPointers
// Adapted for C/C++ by Bj�rn Ganster in 2012-2014
// Copyright X-Ways Software Technology AG
///////////////////////////////////////////////////////////////////////////////

#include "X-Tension.h"

// Please consult
// http://x-ways.com/forensics/x-tensions/api.html
// for current documentation

//fptr_XWF_GetSize XWF_GetSize;

///////////////////////////////////////////////////////////////////////////////
// Variables that store the function pointers

fptr_XWF_GetSize XWF_GetSize;
fptr_XWF_GetVolumeName XWF_GetVolumeName;
fptr_XWF_GetVolumeInformation XWF_GetVolumeInformation;
fptr_XWF_GetSectorContents XWF_GetSectorContents;
fptr_XWF_Read XWF_Read;
fptr_XWF_SelectVolumeSnapshot XWF_SelectVolumeSnapshot;
fptr_XWF_GetVSProp XWF_GetVSProp;
fptr_XWF_GetItemCount XWF_GetItemCount;
fptr_XWF_CreateItem XWF_CreateItem;
fptr_XWF_GetItemName XWF_GetItemName;
fptr_XWF_GetItemSize XWF_GetItemSize;
fptr_XWF_SetItemSize XWF_SetItemSize;
fptr_XWF_GetItemOfs XWF_GetItemOfs;
fptr_XWF_SetItemOfs XWF_SetItemOfs;
fptr_XWF_GetItemInformation XWF_GetItemInformation;
fptr_XWF_SetItemInformation XWF_SetItemInformation;
fptr_XWF_GetItemType XWF_GetItemType;
fptr_XWF_SetItemType XWF_SetItemType;
fptr_XWF_GetItemParent XWF_GetItemParent;
fptr_XWF_SetItemParent XWF_SetItemParent;
fptr_XWF_GetReportTableAssocs XWF_GetReportTableAssocs;
fptr_XWF_AddToReportTable XWF_AddToReportTable;
fptr_XWF_GetComment XWF_GetComment;
fptr_XWF_AddComment XWF_AddComment;
fptr_XWF_OutputMessage XWF_OutputMessage;
fptr_XWF_ShowProgress XWF_ShowProgress;
fptr_XWF_SetProgressPercentage XWF_SetProgressPercentage;
fptr_XWF_SetProgressDescription XWF_SetProgressDescription;
fptr_XWF_ShouldStop XWF_ShouldStop;
fptr_XWF_HideProgress XWF_HideProgress;

fptr_XWF_GetBlock XWF_GetBlock;
fptr_XWF_SetBlock XWF_SetBlock;
fptr_XWF_GetCaseProp XWF_GetCaseProp;
fptr_XWF_GetFirstEvObj XWF_GetFirstEvObj;
fptr_XWF_GetNextEvObj XWF_GetNextEvObj;
fptr_XWF_OpenEvObj XWF_OpenEvObj;
fptr_XWF_CloseEvObj XWF_CloseEvObj;
fptr_XWF_GetEvObjProp XWF_GetEvObjProp;
fptr_XWF_GetExtractedMetadata XWF_GetExtractedMetadata;
fptr_XWF_GetMetadata XWF_GetMetadata;
fptr_XWF_AddExtractedMetadata XWF_AddExtractedMetadata;
fptr_XWF_GetHashValue XWF_GetHashValue;
fptr_XWF_AddEvent XWF_AddEvent;
fptr_XWF_GetReportTableInfo XWF_GetReportTableInfo;
fptr_XWF_GetEvObjReportTableAssocs XWF_GetEvObjReportTableAssocs;

fptr_XWF_SectorIO XWF_SectorIO;


///////////////////////////////////////////////////////////////////////////////
// XT_RetrieveFunctionPointers - call this function before calling anything else

LONG __cdecl XT_RetrieveFunctionPointers(void)
{
	HMODULE Hdl = GetModuleHandle(NULL);

	XWF_GetSize = (fptr_XWF_GetSize) GetProcAddress(Hdl, "XWF_GetSize");
	XWF_GetVolumeName = (fptr_XWF_GetVolumeName) GetProcAddress(Hdl, "XWF_GetVolumeName");
	XWF_GetVolumeInformation = (fptr_XWF_GetVolumeInformation) GetProcAddress(Hdl, "XWF_GetVolumeInformation");
	XWF_GetSectorContents = (fptr_XWF_GetSectorContents) GetProcAddress(Hdl, "XWF_GetSectorContents");
	XWF_Read = (fptr_XWF_Read) GetProcAddress(Hdl, "XWF_Read");

	XWF_SelectVolumeSnapshot = (fptr_XWF_SelectVolumeSnapshot) GetProcAddress(Hdl, "XWF_SelectVolumeSnapshot");
	XWF_GetVSProp = (fptr_XWF_GetVSProp) GetProcAddress(Hdl, "XWF_GetVSProp");
	XWF_GetItemCount = (fptr_XWF_GetItemCount) GetProcAddress(Hdl, "XWF_GetItemCount");

	XWF_CreateItem = (fptr_XWF_CreateItem) GetProcAddress(Hdl, "XWF_CreateItem");
	XWF_GetItemName = (fptr_XWF_GetItemName) GetProcAddress(Hdl, "XWF_GetItemName");
	XWF_GetItemSize = (fptr_XWF_GetItemSize) GetProcAddress(Hdl, "XWF_GetItemSize");
	XWF_SetItemSize = (fptr_XWF_SetItemSize) GetProcAddress(Hdl, "XWF_SetItemSize");
	XWF_GetItemOfs = (fptr_XWF_GetItemOfs) GetProcAddress(Hdl, "XWF_GetItemOfs");
	XWF_SetItemOfs = (fptr_XWF_SetItemOfs) GetProcAddress(Hdl, "XWF_SetItemOfs");
	XWF_GetItemInformation = (fptr_XWF_GetItemInformation) GetProcAddress(Hdl, "XWF_GetItemInformation");
	XWF_SetItemInformation = (fptr_XWF_SetItemInformation) GetProcAddress(Hdl, "XWF_SetItemInformation");
	XWF_GetItemType = (fptr_XWF_GetItemType) GetProcAddress(Hdl, "XWF_GetItemType");
	XWF_SetItemType = (fptr_XWF_SetItemType) GetProcAddress(Hdl, "XWF_SetItemType");
	XWF_GetItemParent = (fptr_XWF_GetItemParent) GetProcAddress(Hdl, "XWF_GetItemParent");
	XWF_SetItemParent = (fptr_XWF_SetItemParent) GetProcAddress(Hdl, "XWF_SetItemParent");
	XWF_GetReportTableAssocs = (fptr_XWF_GetReportTableAssocs) GetProcAddress(Hdl, "XWF_GetReportTableAssocs");
	XWF_AddToReportTable = (fptr_XWF_AddToReportTable) GetProcAddress(Hdl, "XWF_AddToReportTable");
	XWF_GetComment = (fptr_XWF_GetComment) GetProcAddress(Hdl, "XWF_GetComment");
	XWF_AddComment = (fptr_XWF_AddComment) GetProcAddress(Hdl, "XWF_AddComment");

	XWF_OutputMessage = (fptr_XWF_OutputMessage) GetProcAddress(Hdl, "XWF_OutputMessage");
	XWF_ShowProgress = (fptr_XWF_ShowProgress) GetProcAddress(Hdl, "XWF_ShowProgress");
	XWF_SetProgressPercentage = (fptr_XWF_SetProgressPercentage) GetProcAddress(Hdl, "XWF_SetProgressPercentage");
	XWF_SetProgressDescription = (fptr_XWF_SetProgressDescription) GetProcAddress(Hdl, "XWF_SetProgressDescription");
	XWF_ShouldStop = (fptr_XWF_ShouldStop) GetProcAddress(Hdl, "XWF_ShouldStop");
	XWF_HideProgress = (fptr_XWF_HideProgress) GetProcAddress(Hdl, "XWF_HideProgress");

	XWF_GetBlock = (fptr_XWF_GetBlock) GetProcAddress(Hdl, "XWF_GetBlock");
	XWF_SetBlock = (fptr_XWF_SetBlock) GetProcAddress(Hdl, "XWF_SetBlock");
	XWF_GetCaseProp = (fptr_XWF_GetCaseProp) GetProcAddress(Hdl, "XWF_GetCaseProp");
	XWF_GetFirstEvObj = (fptr_XWF_GetFirstEvObj) GetProcAddress(Hdl, "XWF_GetFirstEvObj");
	XWF_GetNextEvObj = (fptr_XWF_GetNextEvObj) GetProcAddress(Hdl, "XWF_GetNextEvObj");
	XWF_OpenEvObj = (fptr_XWF_OpenEvObj) GetProcAddress(Hdl, "XWF_OpenEvObj");
	XWF_CloseEvObj = (fptr_XWF_CloseEvObj) GetProcAddress(Hdl, "XWF_CloseEvObj");
	XWF_GetEvObjProp = (fptr_XWF_GetEvObjProp) GetProcAddress(Hdl, "XWF_GetEvObjProp");
	XWF_GetExtractedMetadata = (fptr_XWF_GetExtractedMetadata) GetProcAddress(Hdl, "XWF_GetExtractedMetadata");
	XWF_GetMetadata = (fptr_XWF_GetMetadata) GetProcAddress(Hdl, "XWF_GetMetadata");
	XWF_AddExtractedMetadata = (fptr_XWF_AddExtractedMetadata) GetProcAddress(Hdl, "XWF_AddExtractedMetadata");
	XWF_GetHashValue = (fptr_XWF_GetHashValue) GetProcAddress(Hdl, "XWF_GetHashValue");
	XWF_AddEvent = (fptr_XWF_AddEvent) GetProcAddress(Hdl, "XWF_AddEvent");
	XWF_GetReportTableInfo = (fptr_XWF_GetReportTableInfo) GetProcAddress(Hdl, "XWF_GetReportTableInfo");
	XWF_GetEvObjReportTableAssocs = (fptr_XWF_GetEvObjReportTableAssocs) GetProcAddress(Hdl, "XWF_GetEvObjReportTableAssocs");

	XWF_SectorIO = (fptr_XWF_SectorIO) GetProcAddress(Hdl, "XWF_SectorIO");

   return 1;
}

