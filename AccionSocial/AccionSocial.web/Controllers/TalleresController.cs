using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace AccionSocial.web.Controllers
{
    public class TalleresController : Controller
    {
        // GET: TalleresController
        public IActionResult AdministracionTalleres()
        {
            return View();
        }


        // GET: TallerController/Details/5
        public ActionResult Details(int id)
        {
            return View();
        }

        // GET: TallerController/Create
        public ActionResult Create()
        {
            return View();
        }

        // POST: TallerController/Create
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Create(IFormCollection collection)
        {
            try
            {
                return RedirectToAction(nameof(Index));
            }
            catch
            {
                return View();
            }
        }

        // GET: TallerController/Edit/5
        public ActionResult Edit(int id)
        {
            return View();
        }

        // POST: TallerController/Edit/5
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Edit(int id, IFormCollection collection)
        {
            try
            {
                return RedirectToAction(nameof(Index));
            }
            catch
            {
                return View();
            }
        }

        // GET: TallerController/Delete/5
        public ActionResult Delete(int id)
        {
            return View();
        }

        // POST: TallerController/Delete/5
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Delete(int id, IFormCollection collection)
        {
            try
            {
                return RedirectToAction(nameof(Index));
            }
            catch
            {
                return View();
            }
        }
    }
}
