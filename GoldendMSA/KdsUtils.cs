using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace GoldendMSA
{
    public class KdsUtils
    {
        public static readonly long KeyCycleDuration = 360000000000;

        public static void GetCurrentIntervalID(
            long kdsKeyCycleDuration, // 360000000000
            int someFlag, // 0
            ref int l0KeyID,
            ref int l1KeyID,
            ref int l2KeyID)
        {
            long currentTime = DateTime.Now.ToFileTimeUtc();
            if (someFlag != 0)
            {
                currentTime += 3000000000;
            }
            int temp = (int)(currentTime / kdsKeyCycleDuration);
            l0KeyID = temp / 1024;
            l1KeyID = (temp / 32) & 31;
            l2KeyID = temp & 31;

            return;
        }
    }
}