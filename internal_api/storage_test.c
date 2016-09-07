/*****************************************************************************
** Copyright (C) 2014 Secure Systems Group.                                 **
** Copyright (C) 2015 Intel Corporation.                                    **
**                                                                          **
** Licensed under the Apache License, Version 2.0 (the "License");          **
** you may not use this file except in compliance with the License.         **
** You may obtain a copy of the License at                                  **
**                                                                          **
**      http://www.apache.org/licenses/LICENSE-2.0                          **
**                                                                          **
** Unless required by applicable law or agreed to in writing, software      **
** distributed under the License is distributed on an "AS IS" BASIS,        **
** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. **
** See the License for the specific language governing permissions and      **
** limitations under the License.                                           **
*****************************************************************************/

/* Extreme simply smoke tests. */

#include "storage_test.h"
#include "../include/tee_internal_api.h"

/* Start Open-TEE spesifics. NOT GP Compliant. For debugin sake */
#include "../include/tee_logging.h"
#define PRI_STR(str)	    OT_LOG1(LOG_DEBUG, str);
#define PRI (str, ...)       OT_LOG1(LOG_DEBUG, "%s : " str "\n",  __func__, ##__VA_ARGS__);
#define PRI_OK(str, ...)    OT_LOG1(LOG_DEBUG, " [OK] : %s : " str "\n",  __func__, ##__VA_ARGS__);
#define PRI_YES(str, ...)   OT_LOG1(LOG_DEBUG, " YES? : %s : " str "\n",  __func__, ##__VA_ARGS__);
#define PRI_FAIL(str, ...)  OT_LOG1(LOG_DEBUG, "FAIL  : %s : " str "\n",  __func__, ##__VA_ARGS__);
#define PRI_ABORT(str, ...) OT_LOG1(LOG_DEBUG, "ABORT!: %s : " str "\n",  __func__, ##__VA_ARGS__);
/* Start Open-TEE spesifics. */

#define KEY_IN_BYTES(key_in_bits) ((key_in_bits + 7) / 8)
#define SIZE_OF_VEC(vec) (sizeof(vec) - 1)

/* RSA (NIST) */
uint8_t modulus[] = "\xa8\xd6\x8a\xcd\x41\x3c\x5e\x19\x5d\x5e\xf0\x4e\x1b\x4f\xaa\xf2"
		    "\x42\x36\x5c\xb4\x50\x19\x67\x55\xe9\x2e\x12\x15\xba\x59\x80\x2a"
		    "\xaf\xba\xdb\xf2\x56\x4d\xd5\x50\x95\x6a\xbb\x54\xf8\xb1\xc9\x17"
		    "\x84\x4e\x5f\x36\x19\x5d\x10\x88\xc6\x00\xe0\x7c\xad\xa5\xc0\x80"
		    "\xed\xe6\x79\xf5\x0b\x3d\xe3\x2c\xf4\x02\x6e\x51\x45\x42\x49\x5c"
		    "\x54\xb1\x90\x37\x68\x79\x1a\xae\x9e\x36\xf0\x82\xcd\x38\xe9\x41"
		    "\xad\xa8\x9b\xae\xca\xda\x61\xab\x0d\xd3\x7a\xd5\x36\xbc\xb0\xa0"
		    "\x94\x62\x71\x59\x48\x36\xe9\x2a\xb5\x51\x73\x01\xd4\x51\x76\xb5";

uint8_t public_exp[] = "\x00\x00\x00\x03";

uint8_t private_exp[] = "\x1c\x23\xc1\xcc\xe0\x34\xba\x59\x8f\x8f\xd2\xb7\xaf\x37\xf1\xd3"
			"\x0b\x09\x0f\x73\x62\xae\xe6\x8e\x51\x87\xad\xae\x49\xb9\x95\x5c"
			"\x72\x9f\x24\xa8\x63\xb7\xa3\x8d\x6e\x3c\x74\x8e\x29\x72\xf6\xd9"
			"\x40\xb7\xba\x89\x04\x3a\x2d\x6c\x21\x00\x25\x6a\x1c\xf0\xf5\x6a"
			"\x8c\xd3\x5f\xc6\xee\x20\x52\x44\x87\x66\x42\xf6\xf9\xc3\x82\x0a"
			"\x3d\x9d\x2c\x89\x21\xdf\x7d\x82\xaa\xad\xca\xf2\xd7\x33\x4d\x39"
			"\x89\x31\xdd\xbb\xa5\x53\x19\x0b\x3a\x41\x60\x99\xf3\xaa\x07\xfd"
			"\x5b\x26\x21\x46\x45\xa8\x28\x41\x9e\x12\x2c\xfb\x85\x7a\xd7\x3b";

static TEE_Result verify_obj_params(TEE_ObjectHandle object,
				    TEE_Attribute *params,
				    uint32_t params_count)
{
	/* NOTE: Only for reference attributes!!
	 * NOTE2: Cant verify if object attribute count is same as fn params count */

	uint32_t obj_attr_len = 0, i = 0;
	void *obj_attr = NULL;
	TEE_Result gp_rv = TEE_SUCCESS;

	for (i = 0; i < params_count; ++i) {
		gp_rv = TEE_GetObjectBufferAttribute(object,
						     params[i].attributeID, NULL, &obj_attr_len);
		if (gp_rv != TEE_ERROR_SHORT_BUFFER) {
			PRI_FAIL("Expected buffer size");
			goto err;
		}

		obj_attr = TEE_Malloc(obj_attr_len, 0);
		if (obj_attr == NULL) {
			PRI_FAIL("TEE_Malloc failed");
			gp_rv = TEE_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		gp_rv = TEE_GetObjectBufferAttribute(object, 123456789, obj_attr, &obj_attr_len);
		if (gp_rv != TEE_ERROR_ITEM_NOT_FOUND) {
			PRI_FAIL("Attribute should not be found, dummy ID");
			goto err;
		}

		gp_rv = TEE_GetObjectBufferAttribute(object, params[i].attributeID,
						     obj_attr, &obj_attr_len);
		if (gp_rv != TEE_SUCCESS) {
			PRI_FAIL("Something is wrong");
			goto err;
		}

		/* Verify attribute */
		if (params[i].content.ref.length =! obj_attr_len) {
			PRI_FAIL("Attribute length is wrong");
			gp_rv = TEE_ERROR_BAD_STATE;
			goto err;
		}

		if (TEE_MemCompare(params[i].content.ref.buffer, obj_attr, obj_attr_len)) {
			PRI_FAIL("Attribute buffer data is wrong");
			gp_rv = TEE_ERROR_BAD_STATE;
			goto err;
		}

		/* Reset buffer */
		TEE_Free(obj_attr);
		obj_attr = NULL;
		obj_attr_len = 0;
	}

err:
	TEE_Free(obj_attr);
	return gp_rv;
}

static uint32_t copy_transient_object()
{
	TEE_ObjectHandle transient_rsa_key = NULL, cpy_transient_rsa_object = NULL;
	uint32_t rsa_size = 1024, param_count = 3, cpy_rsa_size = rsa_size * 2;
	TEE_Attribute params[3] = {0};
	TEE_Result ret = TEE_SUCCESS;
	TEE_ObjectInfo info = {0};

	TEE_InitRefAttribute(&params[0], TEE_ATTR_RSA_MODULUS, modulus, SIZE_OF_VEC(modulus));
	TEE_InitRefAttribute(&params[1], TEE_ATTR_RSA_PUBLIC_EXPONENT, public_exp, SIZE_OF_VEC(public_exp));
	TEE_InitRefAttribute(&params[2], TEE_ATTR_RSA_PRIVATE_EXPONENT, private_exp, SIZE_OF_VEC(private_exp));

	ret = TEE_AllocateTransientObject(TEE_TYPE_RSA_KEYPAIR, rsa_size, &transient_rsa_key);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Transied object alloc failed : 0x%x", ret);
		goto err_1;
	}

	ret = TEE_PopulateTransientObject(transient_rsa_key, params, param_count);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("RSA public key population failed : 0x%x", ret);
		goto err_1;
	}

	ret = verify_obj_params(transient_rsa_key, params, param_count);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Problems with Transient object attributes : 0x%x", ret);
		goto err_1;
	}

	ret = TEE_AllocateTransientObject(TEE_TYPE_RSA_KEYPAIR, cpy_rsa_size, &cpy_transient_rsa_object);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Transied object alloc failed : 0x%x", ret);
		goto err_2;
	}

	TEE_CopyObjectAttributes1(cpy_transient_rsa_object, transient_rsa_key);

	ret = verify_obj_params(cpy_transient_rsa_object, params, param_count);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Problems with copied object attributes : 0x%x", ret);
		goto err_2;
	}

	TEE_GetObjectInfo1(cpy_transient_rsa_object, &info);

	if (info.maxObjectSize != cpy_rsa_size) {
		PRI_FAIL("Copied object max size is wrong");
		ret = TEE_ERROR_BAD_STATE;
		goto err_2;
	}

	if (info.keySize != rsa_size) {
		PRI_FAIL("Copied object key size is wrong");
		ret = TEE_ERROR_BAD_STATE;
		goto err_2;
	}

	if (!(info.handleFlags & TEE_HANDLE_FLAG_INITIALIZED)) {
		PRI_FAIL("Copied object should be initialized");
		ret = TEE_ERROR_BAD_STATE;
		goto err_2;
	}

err_2:
	TEE_FreeTransientObject(cpy_transient_rsa_object);
err_1:
	TEE_FreeTransientObject(transient_rsa_key);
	return ret;
}

static uint32_t create_and_open_verify_attrs()
{
	uint8_t objID[] = "\x89\x31\xdd\xbb\xa5\x53\x19\x0b\x3a\x41\x60\x99\xf3\xaa\x07\xfd";
	uint8_t data[] = "\x5b\x26\x21\x46\x45\xa8\x28\x41\x9e\x12\x2c\xfb\x85\x7a\xd7\x3b";
	TEE_Attribute params[3] = {0};
	uint32_t rsa_size = 1024, param_count = 3;
	TEE_ObjectHandle transient_rsa_key = NULL, persist_rsa_key = NULL,
			open_persist_rsa_key = NULL;
	uint32_t flags = TEE_DATA_FLAG_ACCESS_WRITE |
			 TEE_DATA_FLAG_ACCESS_WRITE_META | TEE_DATA_FLAG_OVERWRITE;
	TEE_Result ret = TEE_SUCCESS;

	TEE_InitRefAttribute(&params[0], TEE_ATTR_RSA_MODULUS, modulus, SIZE_OF_VEC(modulus));
	TEE_InitRefAttribute(&params[1], TEE_ATTR_RSA_PUBLIC_EXPONENT, public_exp, SIZE_OF_VEC(public_exp));
	TEE_InitRefAttribute(&params[2], TEE_ATTR_RSA_PRIVATE_EXPONENT, private_exp, SIZE_OF_VEC(private_exp));

	ret = TEE_AllocateTransientObject(TEE_TYPE_RSA_KEYPAIR, rsa_size, &transient_rsa_key);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Transied object alloc failed : 0x%x", ret);
		goto err_1;
	}

	ret = TEE_PopulateTransientObject(transient_rsa_key, params, param_count);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("RSA public key population failed : 0x%x", ret);
		goto err_1;
	}

	ret = verify_obj_params(transient_rsa_key, params, param_count);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Problems with Transient object attributes : 0x%x", ret);
		goto err_1;
	}

	ret = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE, (void *)objID, SIZE_OF_VEC(objID),
					 flags, transient_rsa_key,
					 data, SIZE_OF_VEC(data),
					 &persist_rsa_key);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Create persisten object failed : 0x%x", ret);
		goto err_1;
	}

	ret = verify_obj_params(persist_rsa_key, params, param_count);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Problems with Created persistent object attributes : 0x%x", ret);
		goto err_2;
	}

	TEE_CloseObject(persist_rsa_key);
	persist_rsa_key = NULL;

	ret = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE, (void *)objID, SIZE_OF_VEC(objID),
				       flags, &open_persist_rsa_key);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Open failed : 0x%x", ret);
		goto err_2;
	}

	ret = verify_obj_params(open_persist_rsa_key, params, param_count);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Problems with Opened persistent object attributes : 0x%x", ret);
		goto err_3;
	}

err_3:
	TEE_CloseAndDeletePersistentObject1(open_persist_rsa_key);
err_2:
	TEE_CloseObject(persist_rsa_key);
err_1:
	TEE_FreeTransientObject(transient_rsa_key);
	return ret;
}

static uint32_t gen_rsa_key_pair_and_save_read()
{
	TEE_Result ret;
	TEE_ObjectHandle handler = (TEE_ObjectHandle)NULL;
	TEE_ObjectHandle handler2 = (TEE_ObjectHandle)NULL;
	size_t key_size = 512;
	char objID[] = "56c5d1b260704de30fe7af67e5b9327613abebe6172a2b4e949d84b8e561e2fb";
	size_t objID_len = 64;
	uint32_t flags = TEE_DATA_FLAG_ACCESS_WRITE |
			 TEE_DATA_FLAG_ACCESS_WRITE_META | TEE_DATA_FLAG_OVERWRITE;
	void *data;
	uint32_t data_len = 12, fn_ret = 1; /* Initialized error return */

	data = TEE_Malloc(data_len, 0);
	if (data == NULL)
		goto err;
	TEE_GenerateRandom(data, data_len);

	ret = TEE_AllocateTransientObject(TEE_TYPE_RSA_KEYPAIR, key_size, &handler);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Transied object alloc failed : 0x%x", ret);
		goto err;
	}

	ret = TEE_GenerateKey(handler, key_size, (TEE_Attribute *)NULL, 0);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("RSA keypair generation failed : 0x%x", ret);
		goto err;
	}

	ret = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE, (void *)objID, objID_len,
					 flags, handler, data, data_len, (TEE_ObjectHandle *)NULL);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Create persisten object failed : 0x%x", ret);
		goto err;
	}

	ret = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE,
				       (void *)objID, objID_len, flags, &handler2);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Open failed : 0x%x", ret);
		goto err;
	}

	fn_ret = 0; /* OK */

err:
	TEE_FreeTransientObject(handler);
	TEE_CloseAndDeletePersistentObject1(handler2);
	TEE_Free(data);

	if (fn_ret == 0)
		PRI_OK("-");

	return fn_ret;
}


static uint32_t popu_rsa_pub_key()
{
	TEE_Result ret;
	TEE_ObjectHandle rsa_pubkey = (TEE_ObjectHandle)NULL;
	uint32_t key_size = 512;
	TEE_Attribute *params = (TEE_Attribute *)NULL;
	uint32_t param_count = 2, fn_ret = 1; /* Initialized error return */

	/* Do malloc */
	params = (TEE_Attribute *)TEE_Malloc(param_count * sizeof(TEE_Attribute), 0);
	if (params == NULL) {
		PRI_FAIL("Out of memory");
		return fn_ret;
	}
	params[0].content.ref.buffer = TEE_Malloc(KEY_IN_BYTES(key_size), 0);
	params[1].content.ref.buffer = TEE_Malloc(KEY_IN_BYTES(key_size), 0);
	if (params[0].content.ref.buffer == NULL || params[1].content.ref.buffer == NULL) {
		PRI_FAIL("Out of memory");
		goto err_1;
	}

	// modulo
	params[0].attributeID = TEE_ATTR_RSA_MODULUS;
	TEE_GenerateRandom(params[0].content.ref.buffer, KEY_IN_BYTES(key_size));
	params[0].content.ref.length = KEY_IN_BYTES(key_size);

	// pub exp (4 byte random, lazyness)
	params[1].attributeID = TEE_ATTR_RSA_PUBLIC_EXPONENT;
	TEE_GenerateRandom(params[1].content.ref.buffer, 4);
	params[1].content.ref.length = 4;


	ret = TEE_AllocateTransientObject(TEE_TYPE_RSA_PUBLIC_KEY, key_size, &rsa_pubkey);
	if (ret == TEE_ERROR_OUT_OF_MEMORY) {
		PRI_FAIL("Transied object alloc failed : 0x%x", ret);
		goto err_2;
	}

	ret = TEE_PopulateTransientObject(rsa_pubkey, params, param_count);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("RSA public key population failed : 0x%x", ret);
		goto err_2;
	}

	fn_ret = 0; /* OK */

err_2:
	TEE_FreeTransientObject(rsa_pubkey);
	TEE_Free(params[0].content.ref.buffer);
	TEE_Free(params[1].content.ref.buffer);
err_1:
	TEE_Free(params);

	if (fn_ret == 0)
		PRI_OK("-");

	return fn_ret;
}

static uint32_t rename_per_obj_and_enum_and_open_renameObj()
{
	TEE_Result ret;
	TEE_ObjectHandle object = (TEE_ObjectHandle)NULL;
	uint32_t flags = TEE_DATA_FLAG_ACCESS_WRITE_META |
			 TEE_DATA_FLAG_ACCESS_WRITE |
			 TEE_DATA_FLAG_OVERWRITE;
	TEE_ObjectEnumHandle iter_enum = (TEE_ObjectEnumHandle)NULL;
	TEE_ObjectInfo info;
	char original_obj_id[TEE_OBJECT_ID_MAX_LEN],
			obj_id[TEE_OBJECT_ID_MAX_LEN], new_obj_id[TEE_OBJECT_ID_MAX_LEN];
	uint32_t original_obj_id_len = 15, obj_id_len = TEE_OBJECT_ID_MAX_LEN,
			new_obj_id_len = 20, fn_ret = 1; /* Initialized error return */

	TEE_GenerateRandom(original_obj_id, original_obj_id_len);
	TEE_GenerateRandom(new_obj_id, new_obj_id_len);

	/* Generate random object with random data */
	ret = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE,
					 (void *)original_obj_id, original_obj_id_len, flags,
					 (TEE_ObjectHandle)NULL,
					 original_obj_id, original_obj_id_len, &object);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Create persisten object failed : 0x%x", ret);
		goto err;
	}

	ret = TEE_AllocatePersistentObjectEnumerator(&iter_enum);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Enumerator allocation failed : 0x%x", ret);
		goto err;
	}

	ret = TEE_StartPersistentObjectEnumerator(iter_enum, TEE_STORAGE_PRIVATE);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Enumerator start failed (first) : 0x%x", ret);
		goto err;
	}

	for (;;) {
		obj_id_len = TEE_OBJECT_ID_MAX_LEN;
		ret = TEE_GetNextPersistentObject(iter_enum, &info, obj_id, &obj_id_len);
		if (ret == TEE_SUCCESS) {

			if (obj_id_len == original_obj_id_len &&
			    TEE_MemCompare(original_obj_id, obj_id, obj_id_len) == 0)
				break;
			else
				continue;

		} else if (ret == TEE_ERROR_ITEM_NOT_FOUND) {
			PRI_FAIL("Cant find created object");
			goto err;
		} else {
			PRI_FAIL("Enumerator get next failed : 0x%x", ret);
			goto err;
		}
	}

	ret = TEE_RenamePersistentObject(object, new_obj_id, new_obj_id_len);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Object rename failed : 0x%x", ret);
		goto err;
	}

	ret = TEE_StartPersistentObjectEnumerator(iter_enum, TEE_STORAGE_PRIVATE);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Enumerator start failed (second) : 0x%x", ret);
		goto err;
	}

	for (;;) {
		obj_id_len = TEE_OBJECT_ID_MAX_LEN;
		ret = TEE_GetNextPersistentObject(iter_enum, &info, obj_id, &obj_id_len);
		if (ret == TEE_SUCCESS) {

			if (obj_id_len == new_obj_id_len &&
			    TEE_MemCompare(new_obj_id, obj_id, obj_id_len) == 0)
				break;
			else
				continue;

		} else if (ret == TEE_ERROR_ITEM_NOT_FOUND) {
			PRI_FAIL("Cant find renamed object");
			goto err;
		} else {
			PRI_FAIL("Enumerator get next failed : 0x%x", ret);
			goto err;
		}
	}

	/* Continue to end */
	for (;;) {
		obj_id_len = TEE_OBJECT_ID_MAX_LEN;
		ret = TEE_GetNextPersistentObject(iter_enum, &info, obj_id, &obj_id_len);
		if (ret == TEE_SUCCESS) {
			continue;

		} else if (ret == TEE_ERROR_ITEM_NOT_FOUND) {
			break;

		} else {
			PRI_FAIL("Enumerator get next failed : 0x%x", ret);
			goto err;
		}
	}

	fn_ret = 0; /* OK */

err:
	TEE_CloseAndDeletePersistentObject1(object);
	TEE_FreePersistentObjectEnumerator(iter_enum);

	if (fn_ret == 0)
		PRI_OK("-");

	return fn_ret;
}

static uint32_t data_stream_write_read()
{

	TEE_Result ret;
	TEE_ObjectHandle key = (TEE_ObjectHandle)NULL, per_han = (TEE_ObjectHandle)NULL;
	size_t key_size = 256;
	char objID[] = "96c5d1b260704de30fe7af67e5b9327613abebe6172a2b4e949d84b8e561e2fb";
	size_t objID_len = 64;
	uint32_t flags = TEE_DATA_FLAG_ACCESS_WRITE_META | TEE_DATA_FLAG_OVERWRITE |
			 TEE_DATA_FLAG_ACCESS_READ | TEE_DATA_FLAG_ACCESS_WRITE;
	char write_data[50] = {0}, read_data[100] = {0};
	size_t write_data_len = 50, read_data_buf = 100;
	uint32_t count = 0, fn_ret = 1; /* Initialized error return */
	TEE_ObjectInfo info;

	TEE_GenerateRandom(write_data, write_data_len);

	ret = TEE_AllocateTransientObject(TEE_TYPE_AES, key_size, &key);
	if (ret == TEE_ERROR_OUT_OF_MEMORY) {
		PRI_FAIL("Transied object alloc failed : 0x%x", ret);
		goto err;
	}

	ret = TEE_GenerateKey(key, key_size, (TEE_Attribute *)NULL, 0);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("AES key generation failed : 0x%x", ret);
		goto err;
	}

	ret = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE,
					 (void *)objID, objID_len, flags, key, NULL, 0, &per_han);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Create persisten object failed : 0x%x", ret);
		goto err;
	}

	ret = TEE_WriteObjectData(per_han, write_data, write_data_len);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Write failed : 0x%x", ret);
		goto err;
	}

	ret = TEE_SeekObjectData(per_han, 0, TEE_DATA_SEEK_SET);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Seek failed : 0x%x", ret);
		goto err;
	}

	ret = TEE_ReadObjectData(per_han, read_data, read_data_buf, &count);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Read failed : 0x%x", ret);
		goto err;
	}

	if (count != write_data_len || TEE_MemCompare(read_data, write_data, count)) {
		PRI_FAIL("Read data is not sames as written data");
		goto err;
	}

	ret = TEE_SeekObjectData(per_han, -(int32_t)count, TEE_DATA_SEEK_CUR);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Seek failed (second) : 0x%x", ret);
		goto err;
	}

	ret = TEE_ReadObjectData(per_han, read_data, read_data_buf, &count);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Read failed (second) : 0x%x", ret);
		goto err;
	}

	if (count != write_data_len || TEE_MemCompare(read_data, write_data, count)) {
		PRI_FAIL("Read data is not sames as written data (second)");
		goto err;
	}

	ret = TEE_SeekObjectData(per_han, -(int32_t)count, TEE_DATA_SEEK_END);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Seek failed (third) : 0x%x", ret);
		goto err;
	}

	ret = TEE_ReadObjectData(per_han, read_data, read_data_buf, &count);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Read failed (third) : 0x%x", ret);
		goto err;
	}

	if (count != write_data_len || TEE_MemCompare(read_data, write_data, count)) {
		PRI_FAIL("Read data is not sames as written data (third)");
		goto err;
	}

	ret = TEE_SeekObjectData(per_han, 5, TEE_DATA_SEEK_SET);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Seek failed (fourth) : 0x%x", ret);
		goto err;
	}

	ret = TEE_ReadObjectData(per_han, read_data, 1, &count);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Read failed (third) : 0x%x", ret);
		goto err;
	}

	if (count != 1 || TEE_MemCompare(write_data + 5, read_data, count)) {
		PRI_FAIL("Read byte does not matchs");
		goto err;
	}

	TEE_GetObjectInfo1(per_han, &info);
	if (info.dataSize != write_data_len) {
		PRI_FAIL("Object data size is not matching");
		goto err;
	}

	if (info.dataPosition != 6) {
		PRI_FAIL("Incorrect position");
		goto err;
	}

	fn_ret = 0; /* OK */

err:
	TEE_CloseAndDeletePersistentObject1(per_han);
	TEE_CloseObject(key);

	if (fn_ret == 0)
		PRI_OK("-");

	return fn_ret;
}

static uint32_t object_data_size()
{
	TEE_Result ret;
	TEE_ObjectHandle handler = (TEE_ObjectHandle)NULL;
	char objID[] = "34c5d1b260704de30fe7af67e5b9327613abebe6172a2b4e949d84b8e561e2fb";
	size_t objID_len = 64;
	uint32_t flags = TEE_DATA_FLAG_ACCESS_WRITE |
			 TEE_DATA_FLAG_ACCESS_WRITE_META | TEE_DATA_FLAG_OVERWRITE;
	uint32_t data_len = 12, fn_ret = 1; /* Initialized error return */
	char data[12] = {1};
	TEE_ObjectInfo info;

	ret = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE, (void *)objID, objID_len, flags,
					 (TEE_ObjectHandle)NULL, data, data_len,
					 (TEE_ObjectHandle *)NULL);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Create persisten object failed : 0x%x", ret);
		goto err;
	}

	ret = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE,
				       (void *)objID, objID_len, flags, &handler);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Open failed : 0x%x", ret);
		goto err;
	}

	TEE_GetObjectInfo1(handler, &info);

	if (info.dataSize != data_len) {
		PRI_FAIL("Data size is not correct");
		goto err;
	}

	fn_ret = 0; /* OK */

err:
	TEE_CloseAndDeletePersistentObject1(handler);

	if (fn_ret == 0)
		PRI_OK("-");

	return fn_ret;
}

static uint32_t multiple_writes()
{

	TEE_Result ret;
	TEE_ObjectHandle key = (TEE_ObjectHandle)NULL, object = (TEE_ObjectHandle)NULL;
	char objID[] = "96c5d1b260704de30fedaf67e5b9227613abebe6172a2b4e949d84b8e561e2fb";
	size_t objID_len = 64;
	uint32_t flags = TEE_DATA_FLAG_ACCESS_WRITE_META | TEE_DATA_FLAG_OVERWRITE |
			 TEE_DATA_FLAG_ACCESS_READ | TEE_DATA_FLAG_ACCESS_WRITE;
	char write_data[50] = {0}, read_data[100] = {0};
	size_t write_data_len = 50;
	uint32_t read_bytes = 0, write_count = 3, i = 0, fn_ret = 1; /* Initialized error return */
	TEE_ObjectInfo info;

	TEE_GenerateRandom(write_data, write_data_len);

	ret = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE,
					 (void *)objID, objID_len, flags, key, NULL, 0, &object);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Create persisten object failed : 0x%x", ret);
		goto err;
	}

	TEE_GetObjectInfo1(object, &info);

	if (info.dataSize != 0) {
		PRI_FAIL("Object data size should be zero");
		goto err;
	}

	if (info.dataPosition != 0) {
		PRI_FAIL("Object data position be zero");
		goto err;
	}

	for (i = 0; i < write_count; i++) {
		ret = TEE_WriteObjectData(object, write_data, write_data_len);
		if (ret != TEE_SUCCESS) {
			PRI_FAIL("Write failed (%u) : 0x%x", i, ret);
			goto err;
		}
	}

	TEE_GetObjectInfo1(object, &info);

	if (info.dataSize != write_data_len * write_count) {
		PRI_FAIL("Object data size is not matching");
		goto err;
	}

	if (info.dataPosition != write_data_len * write_count) {
		PRI_FAIL("Incorrect position");
		goto err;
	}

	ret = TEE_SeekObjectData(object, write_data_len, TEE_DATA_SEEK_SET);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Seek failed : 0x%x", ret);
		goto err;
	}

	ret = TEE_ReadObjectData(object, read_data, write_data_len, &read_bytes);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Write failed : 0x%x", ret);
		goto err;
	}

	if (read_bytes != write_data_len || TEE_MemCompare(write_data, read_data, write_data_len)) {
		PRI_FAIL("Read data should be same as write data");
		goto err;
	}

	TEE_GetObjectInfo1(object, &info);

	if (info.dataSize != write_data_len * write_count) {
		PRI_FAIL("Object data size is not matching (second)");
		goto err;
	}

	if (info.dataPosition != write_data_len + write_data_len) {
		PRI_FAIL("Incorrect position (second)");
		goto err;
	}

	ret = TEE_SeekObjectData(object, 25, TEE_DATA_SEEK_CUR);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Seek failed (second) : 0x%x", ret);
		goto err;
	}

	TEE_GetObjectInfo1(object, &info);

	if (info.dataPosition != write_data_len + write_data_len + 25) {
		PRI_FAIL("Incorrect position (third)");
		goto err;
	}

	ret = TEE_ReadObjectData(object, read_data, 25, &read_bytes);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Write failed (second) : 0x%x", ret);
		goto err;
	}

	if (read_bytes != 25 || TEE_MemCompare(write_data + 25, read_data, 25)) {
		PRI_FAIL("Read data should be same as write data (second)");
		goto err;
	}

	fn_ret = 0; /* OK */

err:
	TEE_CloseAndDeletePersistentObject1(object);

	if (fn_ret == 0)
		PRI_OK("-");

	return fn_ret;
}

static uint32_t persisten_object_write_and_read()
{

	TEE_Result ret;
	TEE_ObjectHandle object = (TEE_ObjectHandle)NULL;
	char objID[] = "96c5d1b260704de30fedaf67e5b9227613abebff172a2b4e949d84b8e561e2fb";
	size_t objID_len = 64;
	uint32_t flags = TEE_DATA_FLAG_ACCESS_WRITE_META | TEE_DATA_FLAG_OVERWRITE |
			 TEE_DATA_FLAG_ACCESS_READ | TEE_DATA_FLAG_ACCESS_WRITE;
	char write_data[50] = {0}, read_data[100] = {0};
	size_t write_data_len = 50;
	uint32_t read_bytes = 0, write_count = 3, i = 0, fn_ret = 1; /* Initialized error return */
	TEE_ObjectInfo info;

	TEE_GenerateRandom(write_data, write_data_len);

        ret = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE, objID, objID_len, flags, &object);
        if (ret == TEE_SUCCESS) {
                PRI_FAIL("Open session should fail, because object is not existing");
                goto err;
	} else if (ret == TEE_ERROR_ITEM_NOT_FOUND) {
		/* OK */
	} else {
		PRI_FAIL("TEE_OpenPersistentObject : 0x%x", ret);
		goto err;
	}

	ret = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE, (void *)objID, objID_len, flags,
					 (TEE_ObjectHandle)NULL, NULL, 0, &object);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Create persisten object failed : 0x%x", ret);
		goto err;
	}

	for (i = 0; i < write_count; i++) {
		ret = TEE_WriteObjectData(object, write_data, write_data_len);
		if (ret != TEE_SUCCESS) {
			PRI_FAIL("Write failed (%u) : 0x%x", i, ret);
			goto err;
		}
	}

	TEE_CloseObject(object);
	object = (TEE_ObjectHandle)NULL;

	ret = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE,
				       (void *)objID, objID_len, flags, &object);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Open failed : 0x%x", ret);
		goto err;
	}

	TEE_GetObjectInfo1(object, &info);

	if (info.dataSize != write_data_len * write_count) {
		PRI_FAIL("Object data size is not matching");
		goto err;
	}

	if (info.dataPosition != 0) {
		PRI_FAIL("Object data position be zero");
		goto err;
	}

	ret = TEE_ReadObjectData(object, read_data, write_data_len, &read_bytes);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Write failed : 0x%x", ret);
		goto err;
	}

	if (read_bytes != write_data_len || TEE_MemCompare(write_data, read_data, write_data_len)) {
		PRI_FAIL("Read data should be same as write data");
		goto err;
	}

	TEE_GetObjectInfo1(object, &info);

	if (info.dataSize != write_data_len * write_count) {
		PRI_FAIL("Object data size is not matching (second)");
		goto err;
	}

	ret = TEE_SeekObjectData(object, 25, TEE_DATA_SEEK_CUR);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Seek failed (second) : 0x%x", ret);
		goto err;
	}

	ret = TEE_ReadObjectData(object, read_data, 25, &read_bytes);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Write failed (second) : 0x%x", ret);
		goto err;
	}

	if (read_bytes != 25 || TEE_MemCompare(write_data + 25, read_data, 25)) {
		PRI_FAIL("Read data should be same as write data (second)");
		goto err;
	}

	TEE_GetObjectInfo1(object, &info);

	if (info.dataSize != write_data_len * write_count) {
		PRI_FAIL("Object data size is not matching (third)");
		goto err;
	}

	if (info.dataPosition != write_data_len + write_data_len) {
		PRI_FAIL("Incorrect position (third)");
		goto err;
	}

	fn_ret = 0; /* OK */

err:
	TEE_CloseAndDeletePersistentObject1(object);

	if (fn_ret == 0)
		PRI_OK("-");

	return fn_ret;
}

static uint32_t persisten_object_init_data()
{

	TEE_Result ret;
	TEE_ObjectHandle object = (TEE_ObjectHandle)NULL;
	char objID[] = "96c5d1b260aa4de30fedaf67e5b9227613abebff172a2b4e949d84b8e561e2fb";
	size_t objID_len = 64;
	uint32_t flags = TEE_DATA_FLAG_ACCESS_WRITE_META | TEE_DATA_FLAG_OVERWRITE |
			 TEE_DATA_FLAG_ACCESS_READ | TEE_DATA_FLAG_ACCESS_WRITE;
	char write_data[50] = {0}, read_data[100] = {0};
	size_t write_data_len = 20;
	uint32_t read_bytes = 0, fn_ret = 1; /* Initialized error return */
	TEE_ObjectInfo info;

	TEE_GenerateRandom(write_data, write_data_len);

	ret = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE, (void *)objID, objID_len, flags,
					 (TEE_ObjectHandle)NULL,
					 write_data, write_data_len, (TEE_ObjectHandle *)NULL);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Create persisten object failed : 0x%x", ret);
		goto err;
	}

	ret = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE,
				       (void *)objID, objID_len, flags, &object);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Open failed : 0x%x", ret);
		goto err;
	}

	TEE_GetObjectInfo1(object, &info);

	if (info.dataSize != write_data_len) {
		PRI_FAIL("Object init size is not correct after open");
		goto err;
	}

	ret = TEE_ReadObjectData(object, read_data, write_data_len, &read_bytes);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Read failed : 0x%x", ret);
		goto err;
	}

	if (read_bytes != write_data_len || TEE_MemCompare(write_data, read_data, write_data_len)) {
		PRI_FAIL("Not same init data");
		goto err;
	}

	/* Gen new data */
	write_data_len = write_data_len * 2;
	TEE_GenerateRandom(write_data, write_data_len);

	ret = TEE_SeekObjectData(object, 0, TEE_DATA_SEEK_SET);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Seek failed : 0x%x", ret);
		goto err;
	}

	ret = TEE_WriteObjectData(object, write_data, write_data_len);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Write failed (second) : 0x%x", ret);
		goto err;
	}

	TEE_CloseObject(object);
	object = (TEE_ObjectHandle)NULL;

	ret = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE,
				       (void *)objID, objID_len, flags, &object);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Open failed (second) : 0x%x", ret);
		goto err;
	}

	TEE_GetObjectInfo1(object, &info);

	if (info.dataSize != write_data_len) {
		PRI_FAIL("Object size is not correct after open (second)");
		goto err;
	}

	ret = TEE_ReadObjectData(object, read_data, write_data_len, &read_bytes);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Read failed (second) : 0x%x", ret);
		goto err;
	}

	if (read_bytes != write_data_len || TEE_MemCompare(write_data, read_data, write_data_len)) {
		PRI_FAIL("Not data is not updated (second)");
		goto err;
	}

	fn_ret = 0; /* OK */

err:
	TEE_CloseAndDeletePersistentObject1(object);

	if (fn_ret == 0)
		PRI_OK("-");

	return fn_ret;
}

static uint32_t overwrite_persisten()
{

	TEE_Result ret;
	TEE_ObjectHandle object = (TEE_ObjectHandle)NULL;
	char objID[] = "96c5d1b260aa4de30fedaf67e5b9227613abebff172a2b4e949994b8e561e2fb";
	size_t objID_len = 64;
	uint32_t flags = TEE_DATA_FLAG_ACCESS_WRITE_META |
			 TEE_DATA_FLAG_ACCESS_READ | TEE_DATA_FLAG_ACCESS_WRITE;
	uint32_t counter = 1, read_bytes = 0, fn_ret = 1; /* Initialized error return */
	char read_data[10];
	TEE_ObjectInfo info;

	ret = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE, (void *)objID, objID_len,
					 TEE_DATA_FLAG_ACCESS_WRITE_META,
					 (TEE_ObjectHandle)NULL, (void *)&counter, sizeof(counter),
					 (TEE_ObjectHandle *)NULL);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Create persisten object failed : 0x%x", ret);
		goto err;
	}

	ret = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE, (void *)objID, objID_len,
					 TEE_DATA_FLAG_ACCESS_WRITE_META,
					 (TEE_ObjectHandle)NULL, (void *)&counter, sizeof(counter),
					 (TEE_ObjectHandle *)NULL);
	if (ret == TEE_SUCCESS) {
		PRI_FAIL("Should not returning TEE_SUCCESs, because overwrite flag is not set");
		goto err;
	} else if (ret == TEE_ERROR_ACCESS_CONFLICT) {
		/* OK */
	} else {
		PRI_FAIL("Create random error : 0x%x", ret);
		goto err;
	}

	/* Open and update counter */
	ret = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE,
				       (void *)objID, objID_len, flags, &object);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Open failed : 0x%x", ret);
		goto err;
	}

	TEE_GetObjectInfo1(object, &info);

	if (info.dataSize != sizeof(counter)) {
		PRI_FAIL("Object init size is not correct after open");
		goto err;
	}

	ret = TEE_ReadObjectData(object, read_data, sizeof(counter), &read_bytes);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Read failed : 0x%x", ret);
		goto err;
	}

	if (read_bytes != sizeof(counter) || TEE_MemCompare(&counter, read_data, sizeof(counter))) {
		PRI_FAIL("Not same init data");
		goto err;
	}

	counter++;

	ret = TEE_SeekObjectData(object, 0, TEE_DATA_SEEK_SET);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Seek failed : 0x%x", ret);
		goto err;
	}

	ret = TEE_WriteObjectData(object, &counter, sizeof(counter));
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Write failed (second) : 0x%x", ret);
		goto err;
	}

	TEE_CloseObject(object);

	/* Re open and read data */
	ret = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE,
				       (void *)objID, objID_len, flags, &object);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Open failed (second) : 0x%x", ret);
		goto err;
	}

	TEE_GetObjectInfo1(object, &info);

	if (info.dataSize != sizeof(counter)) {
		PRI_FAIL("Object size is not correct after open (second)");
		goto err;
	}

	ret = TEE_ReadObjectData(object, read_data, sizeof(counter), &read_bytes);
	if (ret != TEE_SUCCESS) {
		PRI_FAIL("Read failed (second) : 0x%x", ret);
		goto err;
	}

	if (read_bytes != sizeof(counter) || TEE_MemCompare(&counter, read_data, sizeof(counter))) {
		PRI_FAIL("Not data is not updated (second)");
		goto err;
	}

	fn_ret = 0; /* OK */

err:
	TEE_CloseAndDeletePersistentObject1(object);

	if (fn_ret == 0)
		PRI_OK("-");

	return fn_ret;
}

uint32_t storage_test(uint32_t loop_count)
{
	uint32_t i, test_have_fail = 0;

	PRI_STR("START: storage tests");

	PRI_STR("----Begin-with-test-cases----\n");

	for (i = 0; i < loop_count; ++i) {

		if (copy_transient_object() ||
		    create_and_open_verify_attrs() ||
		    gen_rsa_key_pair_and_save_read() ||
		    popu_rsa_pub_key() ||
		    rename_per_obj_and_enum_and_open_renameObj() ||
		    data_stream_write_read() ||
		    object_data_size() ||
		    multiple_writes() ||
		    persisten_object_write_and_read() ||
		    persisten_object_init_data() ||
		    overwrite_persisten()) {
			test_have_fail = 1;
			break;
		}
	}

	PRI_STR("----Test-has-reached-end----\n");

	PRI_STR("END: storage tests");

	return test_have_fail ? 1 : 0;
}
