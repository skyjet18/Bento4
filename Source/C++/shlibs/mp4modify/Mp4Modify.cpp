/*****************************************************************
|
|    AP4 - MP4 File Processor
|
|    Copyright 2002-2008 Axiomatic Systems, LLC
|
|
|    This file is part of Bento4/AP4 (MP4 Atom Processing Library).
|
|    Unless you have obtained Bento4 under a difference license,
|    this version of Bento4 is Bento4|GPL.
|    Bento4|GPL is free software; you can redistribute it and/or modify
|    it under the terms of the GNU General Public License as published by
|    the Free Software Foundation; either version 2, or (at your option)
|    any later version.
|
|    Bento4|GPL is distributed in the hope that it will be useful,
|    but WITHOUT ANY WARRANTY; without even the implied warranty of
|    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
|    GNU General Public License for more details.
|
|    You should have received a copy of the GNU General Public License
|    along with Bento4|GPL; see the file COPYING.  If not, write to the
|    Free Software Foundation, 59 Temple Place - Suite 330, Boston, MA
|    02111-1307, USA.
|
 ****************************************************************/

/*----------------------------------------------------------------------
|   includes
+---------------------------------------------------------------------*/
#include <stdio.h>
#include <stdlib.h>

#include "Ap4.h"
#include "Ap4SgpdAtom.h"


/*----------------------------------------------------------------------
|   AP4_CencRemoveProcessor
+---------------------------------------------------------------------*/

class AP4_CencRemoveProcessor : public AP4_Processor
{
public:
	// methods
	AP4_Result Initialize(AP4_AtomParent &top_level, AP4_ByteStream &stream, ProgressListener* listener)
	{
		// moov/trak/mdia/minf/stbl/stsd/encv/sinf

		AP4_Atom *atom = top_level.FindChild("moov/trak/mdia/minf/stbl/stsd");
		if (atom == NULL) {
			fprintf(stderr, "ERROR: atom 'moov/trak/mdia/minf/stbl/stsd' not found\n");
			return AP4_FAILURE;
		}

		/* look for encv or enca atom */
		AP4_StsdAtom *stsd = AP4_DYNAMIC_CAST(AP4_StsdAtom, atom);
		atom = stsd->GetChild(AP4_ATOM_TYPE_ENCV);
		if( atom == NULL )
		{
			atom = stsd->GetChild(AP4_ATOM_TYPE_ENCA);
		}

		if( atom == NULL )
		{
			fprintf(stderr, "ERROR: encv or enca atom not found - probably not encrypted content ...\n");
			return AP4_FAILURE;
		}

		AP4_Atom *sinf = AP4_DYNAMIC_CAST(AP4_ContainerAtom, atom)->GetChild(AP4_ATOM_TYPE_SINF);

		/* look for frma atom and extract original format */
		AP4_Atom *frma = AP4_DYNAMIC_CAST(AP4_ContainerAtom, sinf)->GetChild(AP4_ATOM_TYPE_FRMA);

		if (frma == NULL) {
			fprintf(stderr, "ERROR: frma atom not found\n");
			return AP4_FAILURE;
		}

		AP4_UI32 original_format = AP4_DYNAMIC_CAST(AP4_FrmaAtom, frma)->GetOriginalFormat();

		char name[5];
		AP4_FormatFourCharsPrintable(name, original_format);

		fprintf(stderr, "INFO: Original format is %s\n", name);

		/* change type of encv or enca atom to original format */
		atom->SetType(original_format);

		/* remove sinf atom (contains info about encryption) */
		sinf->Detach();
		delete sinf;
		return AP4_SUCCESS;
	}
};

//+---------------------------------------------------------------------*/

extern "C" int mp4_cenc_info_remove(char *data, int data_size )
{
	AP4_DataBuffer db_in = AP4_DataBuffer();
	db_in.SetBuffer((AP4_Byte *) data, data_size);
	db_in.SetDataSize(data_size);

	AP4_DataBuffer db_out = AP4_DataBuffer(data_size);

	AP4_MemoryByteStream *input = new AP4_MemoryByteStream(db_in);
	AP4_MemoryByteStream *output = new AP4_MemoryByteStream(db_out);

	AP4_CencRemoveProcessor processor;
	processor.Process(*input, *output);
	input->Release();

	int ret = output->GetDataSize();
	memcpy(data, output->GetData(), ret);
	output->Release();

	return ret;
}

extern "C" int mp4_decrypt(const char *init, int init_size, char *data, int data_size, char **keys )
{
	AP4_ProtectionKeyMap key_map;
	char* keyid_text = NULL;
	char* key_text = NULL;

	fprintf(stderr, "INFO: init size: %d\n", init_size);
	fprintf(stderr, "INFO: data size: %d\n", data_size);

	for( ; *keys; keys++)
	{
		char *key_str = strdup(*keys);

		fprintf(stderr, "INFO: processing key: '%s'\n", key_str);

		if (AP4_SplitArgs(key_str, keyid_text, key_text)) {
			fprintf(stderr, "ERROR: invalid argument for --key option\n");
			free(key_str);
			return 1;
		}

		if( strlen(keyid_text) != 32 || strlen(key_text) != 32 )
		{
			fprintf(stderr, "ERROR: kid:key in wrong format: '%s'\n", key_str);
			free(key_str);
			return -1;
		}

		unsigned char kid[16];
		if (AP4_ParseHex(keyid_text, kid, 16))
		{
			fprintf(stderr, "ERROR: invalid hex format for kid\n");
			free(key_str);
			return -2;
		}

		unsigned char key[16];
		if (AP4_ParseHex(key_text, key, 16))
		{
			fprintf(stderr, "ERROR: invalid hex format for key\n");
			free(key_str);
			return -3;
		}
		key_map.SetKeyForKid(kid, key, 16);
		free(key_str);
	}

	AP4_DataBuffer db_init = AP4_DataBuffer();
	db_init.SetBuffer((AP4_Byte *) init, init_size);
	db_init.SetDataSize(init_size);
	AP4_MemoryByteStream *init_input = new AP4_MemoryByteStream(db_init);

	AP4_DataBuffer db_in = AP4_DataBuffer();
	db_in.SetBuffer((AP4_Byte *) data, data_size);
	db_in.SetDataSize(data_size);
	AP4_MemoryByteStream *input = new AP4_MemoryByteStream(db_in);

	AP4_DataBuffer db_out = AP4_DataBuffer(data_size);
	AP4_MemoryByteStream *output = new AP4_MemoryByteStream(db_out);

	AP4_Processor *processor = new AP4_CencDecryptingProcessor(&key_map);

	AP4_Result result = processor->Process(*input, *output, *init_input);

	init_input->Release();
	input->Release();

	int ret = output->GetDataSize();
	memcpy(data, output->GetData(), ret);
	output->Release();
	delete processor;

	if (AP4_FAILED(result))
	{
		fprintf(stderr, "ERROR: failed to process data (%d)\n", result);
		ret = result;
	}

	return ret;
}

class KidInspector : public AP4_AtomInspector {
public:
	// constructor and destructor
	KidInspector() : m_kid(NULL) {}
	~KidInspector()
	{
		free(m_kid);
	}

	void AddField(const char *name, const unsigned char *data, AP4_Size data_size, FormatHint hint = HINT_NONE)
	{
		if( m_kid == NULL)
		{
			m_kid = (char *) malloc( (2 * data_size) +1 );
			AP4_FormatHex(data, data_size, m_kid);
			m_kid[2 * data_size] = '\0';
		}
	}

	const char *get_kid(void)
	{
		return m_kid ? m_kid : "";
	}


private:
	char *m_kid;

};

class PsshInspector : public AP4_AtomInspector {
public:
	// constructor and destructor
	PsshInspector() : m_wv_found(false), m_wv_system_id{0xed, 0xef, 0x8b, 0xa9, 0x79, 0xd6, 0x4a, 0xce, 0xa3, 0xc8, 0x27, 0xdc, 0xd5, 0x1d, 0x21, 0xed}, m_pssh(NULL), m_pssh_size(0)
	{

	}
	~PsshInspector()
	{
		free(m_pssh);
	}

	void AddField(const char* name, AP4_UI64 value, FormatHint  hint = HINT_NONE)
	{
		if( m_wv_found && strcmp(name, "data_size") == 0)
		{
			m_pssh_size = (AP4_Size) value;
			fprintf(stderr, "INFO: PSSH size: %u\n", m_pssh_size);
		}
	}

	void AddField(const char *name, const unsigned char *data, AP4_Size data_size, FormatHint hint = HINT_NONE)
	{
		if( m_pssh )
		{
			return;
		}

		if(strcmp(name, "system_id") == 0 && memcmp(data, m_wv_system_id, 16) == 0)
		{
			fprintf(stderr, "INFO: found widevine PSSH\n");
			m_wv_found = true;
		}
		else if( strcmp(name, "data") == 0)
		{
			m_pssh = (char *) malloc( (2 * data_size) +1 );
			AP4_FormatHex(data, data_size, m_pssh);
			m_pssh[2 * data_size] = '\0';
			m_wv_found = false;
			fprintf(stderr, "INFO: PSSH: %s\n", m_pssh);
		}
	}

	const char *get_pssh(void)
	{
		return m_pssh ? m_pssh : "";
	}

private:
	bool           m_wv_found;
	unsigned char  m_wv_system_id[16];
	char          *m_pssh;
	AP4_Size       m_pssh_size;
};

extern "C" char *mp4_pssh_get( const char *data, int data_size )
{
	AP4_DataBuffer db_in = AP4_DataBuffer();
	db_in.SetBuffer((AP4_Byte *) data, data_size);
	db_in.SetDataSize(data_size);
	AP4_MemoryByteStream *input = new AP4_MemoryByteStream(db_in);

	// inspect the atoms one by one
	AP4_Atom *atom;
	AP4_DefaultAtomFactory atom_factory;
	KidInspector kid_inspector;
	PsshInspector pssh_inspector;
	pssh_inspector.SetVerbosity(1);

		// parse the atoms
	AP4_AtomParent top_level;
	while (atom_factory.CreateAtomFromStream(*input, atom) == AP4_SUCCESS)
	{
		top_level.AddChild(atom);
	}

	for (AP4_List<AP4_Atom>::Item* item = top_level.GetChildren().FirstItem();
								item;
								item = item->GetNext())
	{
		char name[5];
		AP4_FormatFourCharsPrintable(name, item->GetData()->GetType());
		name[4] = '\0';

		fprintf(stderr, "Found atom: %s\n", name);
	}

	atom = top_level.FindChild("moof/traf/sgpd");
	if (atom == NULL) {
		fprintf(stderr, "ERROR: atom 'moof/traf/sgpd' not found\n");
//		return AP4_FAILURE;
	}
	else
	{
		AP4_SgpdAtom *sgpd = AP4_DYNAMIC_CAST(AP4_SgpdAtom, atom );
		sgpd->Inspect(kid_inspector);
	}

	atom = top_level.FindChild("moof/pssh");
	if (atom == NULL) {
		fprintf(stderr, "ERROR: atom 'moof/pssh' not found\n");
//		return AP4_FAILURE;
	}
	else
	{
		AP4_PsshAtom *pssh = AP4_DYNAMIC_CAST(AP4_PsshAtom, atom );
		pssh->Inspect(pssh_inspector);
	}

	input->Release();

	char *ret = (char *) malloc( strlen(pssh_inspector.get_pssh()) + strlen(kid_inspector.get_kid()) + 2 );

	strcpy(ret, pssh_inspector.get_pssh());
	strcat(ret, ";");
	strcat(ret, kid_inspector.get_kid());
	return ret;
}
