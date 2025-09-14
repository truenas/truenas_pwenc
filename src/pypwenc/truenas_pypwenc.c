#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include "truenas_pypwenc.h"

/* Python object wrapping pwenc_ctx_t */
typedef struct {
	PyObject_HEAD
	pwenc_ctx_t *ctx;
	bool created;
	PyObject *module_ref;  /* Reference to module for accessing module state */
} py_pwenc_ctx_t;

static void
py_pwenc_ctx_dealloc(py_pwenc_ctx_t *self)
{
	pwenc_free_context(self->ctx);
	Py_XDECREF(self->module_ref);
	Py_TYPE(self)->tp_free((PyObject *)self);
}


PyDoc_STRVAR(py_pwenc_ctx_encrypt__doc__,
"encrypt(data) -> bytes\n"
"---------------------\n\n"
"Encrypt data using AES-256-CTR and encode as base64.\n\n"
"Parameters\n"
"----------\n"
"data: bytes\n"
"    Input data to encrypt.\n\n"
"Returns\n"
"-------\n"
"bytes\n"
"    Base64-encoded encrypted data with embedded nonce.\n"
);

static PyObject *
py_pwenc_ctx_encrypt(py_pwenc_ctx_t *self, PyObject *args)
{
	const char *data_in;
	Py_ssize_t data_in_len;
	pwenc_datum_t data_in_datum = {0};
	pwenc_datum_t data_out_datum = {0};
	pwenc_error_t error = {0};
	PyObject *result;
	pwenc_resp_t ret;

	if (!PyArg_ParseTuple(args, "y#", &data_in, &data_in_len))
		return NULL;

	data_in_datum.data = (unsigned char *)data_in;
	data_in_datum.size = data_in_len;

	Py_BEGIN_ALLOW_THREADS
	ret = pwenc_encrypt(self->ctx, &data_in_datum, &data_out_datum, &error);
	Py_END_ALLOW_THREADS

	if (ret != PWENC_SUCCESS) {
		set_exc_from_pwenc(self->module_ref, ret, &error, "Encryption failed");
		return NULL;
	}

	result = PyBytes_FromStringAndSize((char *)data_out_datum.data, data_out_datum.size);
	pwenc_datum_free(&data_out_datum, false);

	return result;
}

PyDoc_STRVAR(py_pwenc_ctx_decrypt__doc__,
"decrypt(data) -> bytes\n"
"---------------------\n\n"
"Decrypt base64-encoded data using AES-256-CTR.\n\n"
"Parameters\n"
"----------\n"
"data: bytes\n"
"    Base64-encoded encrypted data with embedded nonce.\n\n"
"Returns\n"
"-------\n"
"bytes\n"
"    Decrypted plaintext data.\n"
);

static PyObject *
py_pwenc_ctx_decrypt(py_pwenc_ctx_t *self, PyObject *args)
{
	const char *data_in;
	Py_ssize_t data_in_len;
	pwenc_datum_t data_in_datum = {0};
	pwenc_datum_t data_out_datum = {0};
	pwenc_error_t error = {0};
	PyObject *result;
	pwenc_resp_t ret;

	if (!PyArg_ParseTuple(args, "y#", &data_in, &data_in_len))
		return NULL;

	data_in_datum.data = (unsigned char *)data_in;
	data_in_datum.size = data_in_len;

	Py_BEGIN_ALLOW_THREADS
	ret = pwenc_decrypt(self->ctx, &data_in_datum, &data_out_datum, &error);
	Py_END_ALLOW_THREADS

	if (ret != PWENC_SUCCESS) {
		set_exc_from_pwenc(self->module_ref, ret, &error, "Decryption failed");
		return NULL;
	}

	result = PyBytes_FromStringAndSize((char *)data_out_datum.data, data_out_datum.size);
	pwenc_datum_free(&data_out_datum, false);

	return result;
}

static PyObject *
py_pwenc_ctx_get_created(py_pwenc_ctx_t *self, void *closure)
{
	return Py_NewRef(self->created ? Py_True : Py_False);
}

static PyObject *
py_pwenc_ctx_get_path(py_pwenc_ctx_t *self, void *closure)
{
	const char *path = pwenc_get_secret_path(self->ctx);
	if (!path) {
		Py_RETURN_NONE;
	}
	return PyUnicode_FromString(path);
}

static PyObject *
py_pwenc_ctx_repr(py_pwenc_ctx_t *self)
{
	const char *path = pwenc_get_secret_path(self->ctx);
	if (!path) {
		return PyUnicode_FromString("PwencContext(path=None)");
	}
	return PyUnicode_FromFormat("PwencContext(path='%s')", path);
}

static PyGetSetDef py_pwenc_ctx_getsetters[] = {
	{
		.name = "created",
		.get = (getter)py_pwenc_ctx_get_created,
		.doc = "True if the secret file was created, False if it already existed"
	},
	{
		.name = "path",
		.get = (getter)py_pwenc_ctx_get_path,
		.doc = "Path to the secret file used by this context"
	},
	{NULL}
};

static PyMethodDef py_pwenc_ctx_methods[] = {
	{
		.ml_name = "encrypt",
		.ml_meth = (PyCFunction)py_pwenc_ctx_encrypt,
		.ml_flags = METH_VARARGS,
		.ml_doc = py_pwenc_ctx_encrypt__doc__
	},
	{
		.ml_name = "decrypt",
		.ml_meth = (PyCFunction)py_pwenc_ctx_decrypt,
		.ml_flags = METH_VARARGS,
		.ml_doc = py_pwenc_ctx_decrypt__doc__
	},
	{NULL}
};

PyDoc_STRVAR(PwencContextType__doc__,
"PwencContext\n"
"------------\n\n"
"Context for pwenc encryption and decryption operations.\n\n"
"This object provides access to AES-256-CTR encryption/decryption\n"
"using secrets stored in memfd_secret for enhanced security.\n"
"Use truenas_pypwenc.get_context() to create instances.\n"
);

static PyTypeObject PwencContextType = {
	PyVarObject_HEAD_INIT(NULL, 0)
	.tp_name = MODULE_NAME ".PwencContext",
	.tp_doc = PwencContextType__doc__,
	.tp_basicsize = sizeof(py_pwenc_ctx_t),
	.tp_itemsize = 0,
	.tp_flags = Py_TPFLAGS_DEFAULT,
	.tp_new = PyType_GenericNew,
	.tp_dealloc = (destructor)py_pwenc_ctx_dealloc,
	.tp_repr = (reprfunc)py_pwenc_ctx_repr,
	.tp_methods = py_pwenc_ctx_methods,
	.tp_getset = py_pwenc_ctx_getsetters,
};

PyDoc_STRVAR(get_context__doc__,
"get_context(*, create=False, secret_path=None) -> truenas_pypwenc.PwencContext\n"
"----------------------------------------------------------------------------\n\n"
"Create a new PwencContext instance for encryption and decryption operations.\n\n"
"Parameters\n"
"----------\n"
"create: bool, optional (default=False)\n"
"    Whether to create a new secret file if one doesn't exist.\n"
"secret_path: str, optional (default=None)\n"
"    Path to secret file. If None, uses FREENAS_PWENC_SECRET environment\n"
"    variable or falls back to /data/pwenc_secret.\n\n"
"Returns\n"
"-------\n"
"truenas_pypwenc.PwencContext\n"
"    An opened context ready for encryption/decryption operations.\n"
);

static PyObject *
get_context(PyObject *self, PyObject *args, PyObject *kwds)
{
	py_pwenc_ctx_t *ctx;
	int flags = PWENC_OPEN_EXISTING;
	int create = 0;
	const char *secret_path = NULL;
	pwenc_error_t error = {0};
	pwenc_resp_t ret;

	static char *kwlist[] = {"create", "secret_path", NULL};

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "|ps", kwlist, &create, &secret_path))
		return NULL;

	ctx = (py_pwenc_ctx_t *)PyObject_CallObject((PyObject *)&PwencContextType, NULL);
	if (ctx == NULL)
		return NULL;

	ctx->module_ref = Py_NewRef(self);

	if (create) {
		flags |= PWENC_OPEN_CREATE;
	}

	Py_BEGIN_ALLOW_THREADS
	ret = pwenc_init_context(secret_path, &ctx->ctx, &error);
	if (ret == PWENC_SUCCESS) {
		ret = pwenc_open(ctx->ctx, flags, &ctx->created, &error);
	}
	Py_END_ALLOW_THREADS

	if (ret != PWENC_SUCCESS) {
		set_exc_from_pwenc(ctx->module_ref, ret, &error, "Failed to open pwenc context");
		Py_DECREF(ctx);
		return NULL;
	}

	return (PyObject *)ctx;
}

static PyMethodDef truenas_pypwenc_methods[] = {
	{
		.ml_name = "get_context",
		.ml_meth = (PyCFunction)get_context,
		.ml_flags = METH_VARARGS | METH_KEYWORDS,
		.ml_doc = get_context__doc__
	},
	{NULL, NULL, 0, NULL}
};

static int
truenas_pypwenc_module_clear(PyObject *m)
{
	tnpwenc_module_state_t *state = (tnpwenc_module_state_t *)PyModule_GetState(m);
	if (state) {
		Py_CLEAR(state->pwenc_error);
	}
	return 0;
}

static void
truenas_pypwenc_module_free(void *m)
{
	truenas_pypwenc_module_clear((PyObject *)m);
}

static PyModuleDef truenas_pypwenc_module = {
	PyModuleDef_HEAD_INIT,
	.m_name = MODULE_NAME,
	.m_doc = "TrueNAS pwenc library",
	.m_size = sizeof(tnpwenc_module_state_t),
	.m_methods = truenas_pypwenc_methods,
	.m_clear = truenas_pypwenc_module_clear,
	.m_free = truenas_pypwenc_module_free,
};

PyMODINIT_FUNC
PyInit_truenas_pypwenc(void)
{
	PyObject *m;
	tnpwenc_module_state_t *state;

	if (PyType_Ready(&PwencContextType) < 0)
		return NULL;

	m = PyModule_Create(&truenas_pypwenc_module);
	if (m == NULL)
		return NULL;

	state = (tnpwenc_module_state_t *)PyModule_GetState(m);
	if (state == NULL) {
		Py_DECREF(m);
		return NULL;
	}

	/* Create PwencError exception */
	state->pwenc_error = setup_pwenc_exception();
	if (state->pwenc_error == NULL) {
		Py_DECREF(m);
		return NULL;
	}

	if (PyModule_AddObjectRef(m, "PwencError", state->pwenc_error) < 0) {
		Py_DECREF(m);
		return NULL;
	}

	/* Add module constants */
	if (PyModule_AddStringConstant(m, "DEFAULT_SECRET_PATH", PWENC_DEFAULT_SECRET_PATH) < 0) {
		Py_DECREF(m);
		return NULL;
	}

	return m;
}
