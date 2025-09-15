// SPDX-License-Identifier: LGPL-3.0-or-later
#define PY_SSIZE_T_CLEAN
#include <string.h>
#include "truenas_pypwenc.h"

static PyObject *PyExc_PwencError = NULL;

PyDoc_STRVAR(py_pwenc_error__doc__,
"PwencError(exception)\n"
"--------------------\n\n"
"Python wrapper around pwenc library errors.\n\n"
"attributes:\n"
"-----------\n"
"code: int\n"
"    pwenc error code\n"
"message: str\n"
"    human-readable error description\n"
);

const char *pwenc_error_code_to_string(pwenc_resp_t code)
{
	switch (code) {
	case PWENC_SUCCESS:
		return "PWENC_SUCCESS";
	case PWENC_ERROR_INVALID_INPUT:
		return "PWENC_ERROR_INVALID_INPUT";
	case PWENC_ERROR_MEMORY:
		return "PWENC_ERROR_MEMORY";
	case PWENC_ERROR_CRYPTO:
		return "PWENC_ERROR_CRYPTO";
	case PWENC_ERROR_IO:
		return "PWENC_ERROR_IO";
	case PWENC_ERROR_SECRET_NOT_FOUND:
		return "PWENC_ERROR_SECRET_NOT_FOUND";
	case PWENC_ERROR_PAYLOAD_TOO_LARGE:
		return "PWENC_ERROR_PAYLOAD_TOO_LARGE";
	default:
		return "PWENC_ERROR_UNKNOWN";
	}
}

PyObject *setup_pwenc_exception(void)
{
	PyObject *dict = NULL;

	dict = Py_BuildValue("{s:i,s:s}",
			     "code", 0,
			     "message", "");
	if (dict == NULL)
		return NULL;

	PyExc_PwencError = PyErr_NewExceptionWithDoc(MODULE_NAME ".PwencError",
						    py_pwenc_error__doc__,
						    PyExc_RuntimeError,
						    dict);

	Py_DECREF(dict);
	return PyExc_PwencError;
}


void
set_exc_from_pwenc(PyObject *module_ref, pwenc_resp_t code, pwenc_error_t *pwenc_err, const char *additional_info)
{
	PyObject *v = NULL;
	PyObject *args = NULL;
	PyObject *attrs = NULL;
	PyObject *errstr = NULL;
	const char *code_str;
	int err;
	tnpwenc_module_state_t *state;

	if (!module_ref) {
		PyErr_SetString(PyExc_RuntimeError, "Module reference not available");
		return;
	}

	state = (tnpwenc_module_state_t *)PyModule_GetState(module_ref);
	if (!state || !state->pwenc_error) {
		PyErr_SetString(PyExc_RuntimeError, "PwencError not initialized");
		return;
	}

	code_str = pwenc_error_code_to_string(code);

	if (additional_info && pwenc_err && pwenc_err->message[0]) {
		errstr = PyUnicode_FromFormat("[%s]: %s - %s",
					      code_str,
					      additional_info,
					      pwenc_err->message);
	} else if (pwenc_err && pwenc_err->message[0]) {
		errstr = PyUnicode_FromFormat("[%s]: %s",
					      code_str,
					      pwenc_err->message);
	} else {
		errstr = PyUnicode_FromFormat("[%s]: %s",
					      code_str,
					      additional_info ? additional_info : "Unknown error");
	}

	if (errstr == NULL) {
		goto simple_err;
	}

	args = Py_BuildValue("(N)", errstr);
	if (args == NULL) {
		Py_DECREF(errstr);
		goto simple_err;
	}

	v = PyObject_Call(state->pwenc_error, args, NULL);
	if (v == NULL) {
		Py_CLEAR(args);
		return;
	}

	attrs = Py_BuildValue("(is)",
			      code,
			      pwenc_err && pwenc_err->message[0] ? pwenc_err->message : "");

	if (attrs == NULL) {
		Py_XDECREF(v);
		goto simple_err;
	}

	err = PyObject_SetAttrString(v, "code", PyTuple_GetItem(attrs, 0));
	if (err == -1) {
		Py_CLEAR(args);
		Py_CLEAR(v);
		return;
	}

	err = PyObject_SetAttrString(v, "message", PyTuple_GetItem(attrs, 1));
	if (err == -1) {
		Py_CLEAR(args);
		Py_CLEAR(v);
		return;
	}

	PyErr_SetObject(state->pwenc_error, v);
	Py_DECREF(args);
	Py_DECREF(attrs);
	Py_DECREF(v);
	return;

simple_err:
	PyErr_SetString(state->pwenc_error, additional_info ? additional_info : "Unknown pwenc error");
}