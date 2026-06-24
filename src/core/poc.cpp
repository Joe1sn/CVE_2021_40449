#include "include/core/poc.hpp"
using namespace CVE_2021_40449;
namespace offset = exploit::gadget::X_17763_737;
namespace CVE_2021_40449
{

    bool PoC() {

        if (!initAPI())
            return false;


        return true;
    }


} // namespace CVE_2021_40449