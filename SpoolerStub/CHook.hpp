#include <vector>
#include <functional>
#include <iostream>

class CWinVer
{
public:
    CWinVer(){};
    unsigned int minorVersion = 0;
    unsigned int majorVersion = 0;
};
class CMultiPattern
{
public:
    std::function<bool()> _func;
    std::string _pattern;
    CMultiPattern(std::string pattern, std::function<bool()> winVerCheck) : _func(winVerCheck), _pattern(pattern)
    {

    }
}

class CHook
{
public:
    static void Create(std::vector<CMultiPattern> patterns);
    void CHook(void *target, void *detour, void **original)
    {
    }
}