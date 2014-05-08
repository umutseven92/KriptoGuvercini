using Microsoft.Owin;
using Owin;

[assembly: OwinStartupAttribute(typeof(KriptoGuvercini.Startup))]
namespace KriptoGuvercini
{
    public partial class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            ConfigureAuth(app);
        }
    }
}
