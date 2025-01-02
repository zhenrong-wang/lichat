/*
 * Copyright (C) 2022-present Zhenrong WANG
 * This code is distributed under the license: MIT License
 * mailto: zhenrongwang@live.com | X/Twitter: wangzhr4
 */

#ifndef LC_STRINGS_HPP
#define LC_STRINGS_HPP

#include "lc_common.hpp"

#include <unicode/unistr.h>
#include <unicode/ucnv.h>
#include <unicode/ustring.h>

class lc_strings {
public:
// Convert a wide string to UTF-8
    static std::string wstr_to_utf8 (const std::wstring& wstr) {
        //std::wstring_convert<std::codecvt_utf8<wchar_t>> converter;
        //return converter.to_bytes(wstr);
        icu::UnicodeString ustr;
        if constexpr (sizeof(wchar_t) == 2) {
            ustr = icu::UnicodeString{
                reinterpret_cast<const UChar *>(wstr.data()), lc_utils::checked_static_cast<int32_t>(wstr.size())};
        }
        else {
            ustr = icu::UnicodeString::fromUTF32(
                reinterpret_cast<const UChar32 *>(wstr.data()), lc_utils::checked_static_cast<int32_t>(wstr.size()));
        }
        std::string utf8_str;
        ustr.toUTF8String(utf8_str);
        return utf8_str;
    }

    static std::wstring utf8_to_wstr (const std::string& utf8_str) {
        icu::UnicodeString ustr = icu::UnicodeString::fromUTF8(utf8_str);
        std::wstring wstr;
        int32_t required_size = 0;
        UErrorCode uerr = U_ZERO_ERROR;
        if (sizeof(wchar_t) == 2) {
            u_strToWCS(nullptr, 0, &required_size, ustr.getBuffer(), 
                       ustr.length(), &uerr);
            if (U_FAILURE(uerr))
                return L"";
            wstr.resize(required_size);
            u_strToWCS(&wstr[0], lc_utils::checked_static_cast<int32_t>(wstr.size()), nullptr, ustr.getBuffer(),
                       ustr.length(), &uerr);
            if (U_FAILURE(uerr))
                return L"";
            return wstr;
        }
        else {
            int32_t capacity = ustr.countChar32();
            wstr.resize(capacity);
            ustr.toUTF32(reinterpret_cast<UChar32 *>(wstr.data()), capacity, uerr);
            return wstr;
        }
    }

    // Get the real bytes of converted wide string (to UTF-8) 
    static size_t get_wstr_utf8_bytes (const std::wstring& wstr) {
        return wstr_to_utf8(wstr).size();
    }

    // Calculate the actual characters of a UTF-8 string
    static int32_t get_utf8_chars (const std::string& utf8_str) {
        return icu::UnicodeString::fromUTF8(utf8_str).countChar32();
    }

    static size_t get_ustr_print_len (const icu::UnicodeString& ustr) {
        size_t ret = 0;
        auto ustr_len = ustr.length();
        for (int32_t i = 0; i < ustr_len; ) {
            auto wch = ustr.char32At(i);
            if (wch <= static_cast<UChar32>(0x07FF))
                ++ ret;
            else
                ret += 2;
            i = ustr.moveIndex32(i, 1);
        }
        return ret;
    }
};

#endif