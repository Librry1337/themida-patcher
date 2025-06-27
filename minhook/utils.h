#include <jni/jvmti.h>
#include <iostream>

bool contains(const char* str1, const char* str2) {
    return strstr(str1, str2) != NULL;
}
const char* replaceAll(const char* subject, const char* search, const char* replace) {

    size_t subjectLen = strlen(subject);
    size_t searchLen = strlen(search);
    size_t replaceLen = strlen(replace);


    size_t resultLen = 0;
    const char* ptr = subject;
    while ((ptr = strstr(ptr, search)) != nullptr) {
        resultLen += replaceLen - searchLen;
        ptr += searchLen;
    }
    resultLen += subjectLen;


    char* result = new char[resultLen + 1];
    char* resultPtr = result;


    ptr = subject;
    while (*ptr != '\0') {
        if (strncmp(ptr, search, searchLen) == 0) {
            strncpy_s(resultPtr, resultLen + 1 - (resultPtr - result), replace, replaceLen);
            resultPtr += replaceLen;
            ptr += searchLen;
        }
        else {
            *resultPtr++ = *ptr++;
        }
    }
    *resultPtr = '\0';

    return result;
}
const char* jstring2char(JNIEnv* env, jstring jStr) {
    if (!jStr)
        return "";

    const jclass stringClass = env->GetObjectClass(jStr);
    const jmethodID getBytes = env->GetMethodID(stringClass, "getBytes", "(Ljava/lang/String;)[B");
    const jbyteArray stringJbytes = (jbyteArray)env->CallObjectMethod(jStr, getBytes, env->NewStringUTF("UTF-8"));
    const jsize length = env->GetArrayLength(stringJbytes);
    const jbyte* pBytes = env->GetByteArrayElements(stringJbytes, nullptr);
    const char* ret = reinterpret_cast<const char*>(pBytes);

    char* result = new char[length + 1];
    std::memcpy(result, ret, length);
    result[length] = '\0';

    env->ReleaseByteArrayElements(stringJbytes, const_cast<jbyte*>(pBytes), JNI_ABORT);
    env->DeleteLocalRef(stringJbytes);
    env->DeleteLocalRef(stringClass);

    return result;
}

jstring get_interned(JNIEnv* env, jstring value) {
    return (jstring)env->CallObjectMethod(value, env->GetMethodID(env->FindClass(("java/lang/String")), ("intern"), ("()Ljava/lang/String;")));
}

jstring string2jstring(JNIEnv* env, const char* str) {
    jstring jstr = env->NewStringUTF(str);
    jstring bstr = get_interned(env, jstr);
    return (jstring)env->NewGlobalRef(bstr);
}
jclass getObject(JNIEnv* env, jobject classLoader, const char* className)
{
    className = replaceAll(className, "/", ".");
    jstring name = string2jstring(env, className);
    jmethodID mid = env->GetMethodID(env->GetObjectClass(classLoader), ("loadClass"), ("(Ljava/lang/String;)Ljava/lang/Class;"));
    return (jclass)env->CallObjectMethod(classLoader, mid, name);
}
jobject getClassLoader(JNIEnv* env) {
    jclass threadClass = env->FindClass(("java/lang/Thread"));
    jmethodID getAllStackTraces = env->GetStaticMethodID(threadClass, ("getAllStackTraces"), ("()Ljava/util/Map;"));
    jobject stackTracesMap = env->CallStaticObjectMethod(threadClass, getAllStackTraces);

    jclass mapClass = env->FindClass(("java/util/Map"));
    jmethodID keySet = env->GetMethodID(mapClass, ("keySet"), ("()Ljava/util/Set;"));
    jobject threadsSet = env->CallObjectMethod(stackTracesMap, keySet);

    jclass setClass = env->FindClass(("java/util/Set"));
    jmethodID toArray = env->GetMethodID(setClass, ("toArray"), ("()[Ljava/lang/Object;"));
    jobjectArray threads = (jobjectArray)env->CallObjectMethod(threadsSet, toArray);
    jobject classLoader = nullptr;
    jint threadCount = env->GetArrayLength(threads);
    for (int i = 0; i < threadCount; i++) {
        jobject thread = env->GetObjectArrayElement(threads, i);
        jmethodID getName = env->GetMethodID(threadClass, ("getName"), ("()Ljava/lang/String;"));
        jstring name = (jstring)env->CallObjectMethod(thread, getName);
        std::string threadName = jstring2char(env, name);

        if (threadName == ("Render thread")) {
            jmethodID getContextClassLoader = env->GetMethodID(threadClass, ("getContextClassLoader"), ("()Ljava/lang/ClassLoader;"));
            classLoader = env->CallObjectMethod(thread, getContextClassLoader);
            env->DeleteLocalRef(name);
            break;
        }
        env->DeleteLocalRef(name);
    }
    env->DeleteLocalRef(threadClass);
    env->DeleteLocalRef(mapClass);
    env->DeleteLocalRef(setClass);
    return classLoader;
}

const char* getClassName(JNIEnv* env, jclass myCls)
{
    jclass ccls = env->FindClass(("java/lang/Class"));
    jmethodID mid_getName = env->GetMethodID(ccls, ("getName"), ("()Ljava/lang/String;"));
    jstring strObj = (jstring)env->CallObjectMethod(myCls, mid_getName);
    const char* localName = env->GetStringUTFChars(strObj, 0);
    env->ReleaseStringUTFChars(strObj, localName);

    return localName;
}